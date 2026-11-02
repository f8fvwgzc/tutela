//! Binding the two ports, serving, and the graceful shutdown.

use std::future::{Future, IntoFuture as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tonic_health::ServingStatus;
use tonic_health::server::HealthReporter;

use crate::api::{self, AppState};
use crate::authz::grpc::AuthzService;
use crate::cache::TenantCache;
use crate::config::Config;
use crate::db::Db;
use crate::expiry;
use crate::telemetry::Metrics;

/// The bound service, not yet serving.
#[derive(Debug)]
pub struct Server {
    api: TcpListener,
    ops: TcpListener,
    api_router: Router,
    ops_router: Router,
    state: AppState,
    health: HealthReporter,
    drain: Duration,
    stop_timeout: Duration,
    sweep_every: Duration,
}

impl Server {
    /// Binds the two ports over `state`.
    ///
    /// # Errors
    ///
    /// When a port cannot be bound.
    pub async fn bind(config: &Config, state: AppState) -> anyhow::Result<Self> {
        let api = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("binding the API port {}", config.listen))?;
        let ops = TcpListener::bind(config.ops_listen)
            .await
            .with_context(|| format!("binding the ops port {}", config.ops_listen))?;
        let (health, health_service) = tonic_health::server::health_reporter();
        let grpc = tonic::service::Routes::new(health_service)
            .add_service(AuthzService::server(state.clone()))
            .prepare()
            .into_axum_router();
        Ok(Self {
            api_router: api::api_router(&state, grpc, config.request_timeout),
            ops_router: api::ops_router(&state),
            api,
            ops,
            state,
            health,
            drain: config.shutdown_drain,
            stop_timeout: config.shutdown_timeout,
            sweep_every: config.expiry_sweep,
        })
    }

    /// The bound API address.
    ///
    /// # Errors
    ///
    /// When the socket has no local address.
    pub fn api_addr(&self) -> std::io::Result<SocketAddr> {
        self.api.local_addr()
    }

    /// The bound ops address.
    ///
    /// # Errors
    ///
    /// When the socket has no local address.
    pub fn ops_addr(&self) -> std::io::Result<SocketAddr> {
        self.ops.local_addr()
    }

    /// Serves until `shutdown` resolves, then stops in order:
    ///
    /// 1. readiness fails and gRPC health says not serving, while requests
    ///    are still served, for the drain time;
    /// 2. the API port stops taking connections and running requests
    ///    finish, up to the shutdown timeout;
    /// 3. the ops port stops last.
    ///
    /// The expiry sweep runs on a timer until step 2.
    ///
    /// # Errors
    ///
    /// When a listener stops by itself, or requests do not finish in time.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
        let Self {
            api,
            ops,
            api_router,
            ops_router,
            state,
            health,
            drain,
            stop_timeout,
            sweep_every,
        } = self;
        let (stop_api, api_stopped) = watch::channel(false);
        let (stop_ops, ops_stopped) = watch::channel(false);
        let (stop_jobs, jobs_stopped) = watch::channel(false);
        let mut api_task = spawn_listener(api, api_router, api_stopped);
        let mut ops_task = spawn_listener(ops, ops_router, ops_stopped);
        let sweeper = tokio::spawn(expiry::run(
            state.db.clone(),
            Arc::clone(&state.metrics),
            sweep_every,
            jobs_stopped,
        ));

        tokio::select! {
            () = shutdown => {}
            r = &mut api_task => return stopped_by_itself("API", r),
            r = &mut ops_task => return stopped_by_itself("ops", r),
        }

        tracing::info!(drain_ms = drain.as_millis() as u64, "shutting down");
        state.stopping.store(true, Ordering::SeqCst);
        health
            .set_service_status("", ServingStatus::NotServing)
            .await;
        tokio::time::sleep(drain).await;

        let _ = stop_api.send(true);
        let _ = stop_jobs.send(true);
        let finished = tokio::time::timeout(stop_timeout, &mut api_task).await;
        let _ = stop_ops.send(true);
        if tokio::time::timeout(stop_timeout, sweeper).await.is_err() {
            tracing::warn!("the expiry sweep did not stop in time");
        }
        match finished {
            Ok(joined) => {
                joined.context("the API listener panicked")??;
                ops_task.await.context("the ops listener panicked")??;
                tracing::info!("stopped");
                Ok(())
            }
            Err(_) => {
                api_task.abort();
                Err(anyhow!(
                    "requests did not finish within the shutdown timeout"
                ))
            }
        }
    }
}

fn spawn_listener(
    listener: TcpListener,
    router: Router,
    mut stop: watch::Receiver<bool>,
) -> JoinHandle<std::io::Result<()>> {
    let serve = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = stop.wait_for(|stopped| *stopped).await;
        })
        .into_future();
    tokio::spawn(serve)
}

fn stopped_by_itself(
    port: &str,
    joined: Result<std::io::Result<()>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    joined
        .with_context(|| format!("the {port} listener panicked"))?
        .with_context(|| format!("the {port} listener failed"))?;
    bail!("the {port} listener stopped by itself")
}

/// Builds the state from `config`.
///
/// # Errors
///
/// A bad database URL, or a failed JWKS client setup.
pub fn state(config: &Config) -> anyhow::Result<AppState> {
    let db = Db::connect(&config.database_url, config.pool_size)?;
    let metrics = Arc::new(Metrics::new());
    Ok(AppState {
        verifier: Arc::new(config.verifier()?),
        cache: Arc::new(TenantCache::new(
            db.clone(),
            config.limits,
            Arc::clone(&metrics),
        )),
        db,
        metrics,
        stopping: Arc::default(),
        dev_mode: config.dev_mode,
    })
}

/// Runs the service until `shutdown` resolves.
///
/// # Errors
///
/// A failed start, a role or a schema that does not isolate tenants, or a
/// failed shutdown.
pub async fn run(config: Config, shutdown: impl Future<Output = ()> + Send) -> anyhow::Result<()> {
    let state = state(&config)?;
    // A database that is down may come up later. A role that can bypass
    // row-level security never gets to serve.
    match state.db.check_ready().await {
        Err(e) if e.is_unsafe() => {
            return Err(e).context("refusing to serve");
        }
        Err(e) => tracing::warn!(reason = %e, "starting, not ready yet"),
        Ok(()) => {}
    }
    let server = Server::bind(&config, state).await?;
    tracing::info!(
        api = %server.api_addr()?,
        ops = %server.ops_addr()?,
        audience = config.audience.as_str(),
        "serving"
    );
    server.serve(shutdown).await
}

/// `tutelad migrate`: applies the migrations and gives the service role its
/// grants. This is the deploy step that runs as the owner, apart from the
/// service, and it needs no other setting.
///
/// # Errors
///
/// A bad variable, or a failed migration or grant.
pub async fn migrate(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    let get = |name: &str| var(name).filter(|v| !v.is_empty());
    let url = get("TUTELA_OWNER_DATABASE_URL").context("TUTELA_OWNER_DATABASE_URL is not set")?;
    let role = get("TUTELA_SERVICE_ROLE").context("TUTELA_SERVICE_ROLE is not set")?;
    let applied = Db::connect(&url, 1)?.migrate(&role).await?;
    tracing::info!(
        applied = ?applied,
        latest = tutela_store::latest_migration(),
        "the schema is current"
    );
    Ok(())
}
