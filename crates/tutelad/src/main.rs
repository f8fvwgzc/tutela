//! The `tutelad` binary. See the library for what it does.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The Tutela service.
#[derive(Debug, Parser)]
#[command(name = "tutelad", version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve (the default).
    Serve,
    /// As the owner role, apply the migrations and give the service role its
    /// grants. Reads TUTELA_OWNER_DATABASE_URL and TUTELA_SERVICE_ROLE.
    Migrate,
    /// The operator's tenant work, as the owner role (ADR-0041). Reads
    /// TUTELA_OWNER_DATABASE_URL and TUTELA_ISSUER.
    #[command(subcommand)]
    Tenant(TenantCommand),
    /// The operator's apps, for the bootstrap (ADR-0044), as the owner role.
    /// Reads TUTELA_OWNER_DATABASE_URL, TUTELA_ISSUER, TUTELA_MASTER_KEY and
    /// TUTELA_KEY_PEPPER.
    #[command(subcommand)]
    Apps(AppsCommand),
    /// The Helm chart's bootstrap job (ADR-0056), as the owner role:
    /// migrate, then make the tenant, the products' apps, their roles and
    /// webhooks of a plan, unless they are there, and write each secret to
    /// a Kubernetes Secret (or a file). Reads TUTELA_OWNER_DATABASE_URL,
    /// TUTELA_SERVICE_ROLE, TUTELA_ISSUER, TUTELA_MASTER_KEY and
    /// TUTELA_KEY_PEPPER. Prints one JSON line per step, never a secret.
    Bootstrap {
        /// The plan, a JSON file the chart writes from its values.
        #[arg(long)]
        plan: std::path::PathBuf,
        /// Write secrets as files in this directory instead of Kubernetes
        /// Secrets in the pod's namespace.
        #[arg(long)]
        secrets_dir: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AppsCommand {
    /// Make an app of a tenant under TUTELA_ISSUER. Prints its client id,
    /// its service account and its client secret, once, as one line of JSON.
    Create {
        /// The tenant id, `ten_<uuidv7>`.
        #[arg(long)]
        tenant: String,
        /// The app's display name.
        #[arg(long)]
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum TenantCommand {
    /// Make a tenant under TUTELA_ISSUER, with its first org and its first
    /// owners. Prints the new tenant as one line of JSON.
    Create {
        /// The tenant's display name.
        #[arg(long)]
        name: Option<String>,
        /// The first org's display name.
        #[arg(long)]
        org_name: Option<String>,
        /// An owner of the first org: `user:usr_...` or `sa:sa_...`.
        #[arg(long = "admin")]
        admins: Vec<String>,
        /// An owner of the first org by its upstream account, `<iss>=<sub>`:
        /// the person is found or made as token exchange does.
        #[arg(long = "admin-upstream")]
        upstream: Vec<String>,
    },
    /// Print a new tenant id, `ten_<uuidv7>`, for the Helm chart's
    /// `tenant.id` (ADR-0056). It touches no database.
    NewId,
    /// Undo a tenant's soft delete before its purge.
    Restore {
        /// The tenant id, `ten_<uuidv7>`.
        tid: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    // Every Tutela binary installs the one crypto provider itself.
    if tutela_safenet::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("tutelad: a crypto provider is already installed");
        return ExitCode::FAILURE;
    }
    let result = match args.command {
        Some(Command::Migrate) => migrate().await,
        Some(Command::Tenant(t)) => tenant(t).await,
        Some(Command::Apps(a)) => apps(a).await,
        Some(Command::Bootstrap { plan, secrets_dir }) => bootstrap(&plan, secrets_dir).await,
        Some(Command::Serve) | None => serve().await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // The log writer may not be installed yet, so stderr too.
            eprintln!("tutelad: {e:#}");
            tracing::error!(error = %format!("{e:#}"), "tutelad failed");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> anyhow::Result<()> {
    let config = tutelad::Config::from_env()?;
    tutelad::telemetry::init_logs(&config.log)?;
    tutelad::run(config, shutdown_signal()).await
}

async fn migrate() -> anyhow::Result<()> {
    tutelad::telemetry::init_logs("info")?;
    tutelad::server::migrate(|name| std::env::var(name).ok()).await
}

async fn tenant(command: TenantCommand) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if matches!(command, TenantCommand::NewId) {
        println!(
            "{}",
            tutela_contracts::tenant::TenantId::new(
                tutela_contracts::id::Uuid7::from_uuid(uuid::Uuid::now_v7())
                    .map_err(|_| anyhow::anyhow!("a new id is not a UUIDv7"))?
            )
        );
        return Ok(());
    }
    tutelad::telemetry::init_logs("info")?;
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let url = var("TUTELA_OWNER_DATABASE_URL").context("TUTELA_OWNER_DATABASE_URL is not set")?;
    let own: tutela_contracts::tenant::Issuer = var("TUTELA_ISSUER")
        .context("TUTELA_ISSUER is not set")?
        .parse()
        .map_err(|_| anyhow::anyhow!("TUTELA_ISSUER is not an issuer"))?;
    let mut owner = tutelad::lifecycle::connect_owner(&url).await?;
    match command {
        TenantCommand::Create {
            name,
            org_name,
            admins,
            upstream,
        } => {
            let new = tutelad::lifecycle::NewTenant {
                name,
                org_name,
                admins: admins
                    .iter()
                    .map(|a| a.parse())
                    .collect::<Result<_, _>>()
                    .map_err(|_| anyhow::anyhow!("--admin is not a principal"))?,
                upstream_admins: upstream
                    .iter()
                    .map(|u| {
                        let (iss, sub) = u.split_once('=')?;
                        Some((iss.parse().ok()?, sub.to_owned()))
                    })
                    .collect::<Option<_>>()
                    .context("--admin-upstream is <iss>=<sub>")?,
            };
            let made = tutelad::lifecycle::create_tenant(&mut owner, &own, &new).await?;
            println!(
                "{}",
                serde_json::json!({
                    "tid": made.key.tid.to_string(),
                    "iss": made.key.iss.to_string(),
                    "org": made.org.to_string(),
                    "owners": made.owners.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "rev": made.rev,
                })
            );
            Ok(())
        }
        TenantCommand::NewId => Ok(()),
        TenantCommand::Restore { tid } => {
            let tid = tid
                .parse()
                .map_err(|_| anyhow::anyhow!("not a tenant id"))?;
            let key = tutela_contracts::tenant::TenantKey::new(own.clone(), tid);
            tutelad::lifecycle::restore_tenant(&mut owner, &own, &key).await?;
            println!("{}", serde_json::json!({"restored": key.tid.to_string()}));
            Ok(())
        }
    }
}

async fn apps(command: AppsCommand) -> anyhow::Result<()> {
    use anyhow::Context as _;
    tutelad::telemetry::init_logs("info")?;
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let url = var("TUTELA_OWNER_DATABASE_URL").context("TUTELA_OWNER_DATABASE_URL is not set")?;
    let own: tutela_contracts::tenant::Issuer = var("TUTELA_ISSUER")
        .context("TUTELA_ISSUER is not set")?
        .parse()
        .map_err(|_| anyhow::anyhow!("TUTELA_ISSUER is not an issuer"))?;
    let secrets = tutelad::config::Secrets::from_values(
        var("TUTELA_MASTER_KEY").as_deref(),
        var("TUTELA_MASTER_KEY_PREVIOUS").as_deref(),
        var("TUTELA_KEY_PEPPER").as_deref(),
        var("TUTELA_KEY_PEPPER_VERSION").as_deref(),
    )?;
    let mut owner = tutelad::lifecycle::connect_owner(&url).await?;
    match command {
        AppsCommand::Create { tenant, name } => {
            let tid = tenant
                .parse()
                .map_err(|_| anyhow::anyhow!("--tenant is not a tenant id"))?;
            let key = tutela_contracts::tenant::TenantKey::new(own.clone(), tid);
            let (app, secret) =
                tutelad::lifecycle::create_app(&mut owner, &own, &key, &name, &secrets).await?;
            println!(
                "{}",
                serde_json::json!({
                    "client_id": app.id,
                    "principal": app.principal.to_string(),
                    "client_secret": secret.as_str(),
                })
            );
            Ok(())
        }
    }
}

async fn bootstrap(
    plan: &std::path::Path,
    secrets_dir: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use tutelad::bootstrap::{Env, Plan, Sink, kube::Kube};
    tutelad::telemetry::init_logs("info")?;
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let plan = Plan::parse(&std::fs::read_to_string(plan).context("reading the plan")?)?;
    let env = Env {
        owner_url: var("TUTELA_OWNER_DATABASE_URL")
            .context("TUTELA_OWNER_DATABASE_URL is not set")?,
        service_role: var("TUTELA_SERVICE_ROLE").context("TUTELA_SERVICE_ROLE is not set")?,
        own: var("TUTELA_ISSUER")
            .context("TUTELA_ISSUER is not set")?
            .parse()
            .map_err(|_| anyhow::anyhow!("TUTELA_ISSUER is not an issuer"))?,
        secrets: tutelad::config::Secrets::from_values(
            var("TUTELA_MASTER_KEY").as_deref(),
            var("TUTELA_MASTER_KEY_PREVIOUS").as_deref(),
            var("TUTELA_KEY_PEPPER").as_deref(),
            var("TUTELA_KEY_PEPPER_VERSION").as_deref(),
        )?,
        policy: if var("TUTELA_DEV_MODE").as_deref() == Some("1") {
            tutela_safenet::Policy::new().dev_loopback()
        } else {
            tutela_safenet::Policy::new()
        },
    };
    let sink = match secrets_dir {
        Some(dir) => Sink::Dir(dir),
        None => Sink::Kubernetes(Kube::in_cluster(std::path::Path::new(
            tutelad::bootstrap::kube::ACCOUNT_DIR,
        ))?),
    };
    for step in tutelad::bootstrap::run(&plan, &env, &sink).await? {
        println!("{}", serde_json::to_string(&step)?);
    }
    Ok(())
}

/// Resolves on SIGTERM or Ctrl-C. If the handlers cannot be installed, the
/// service would not stop cleanly, so it starts to stop at once.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        tracing::error!("cannot listen for SIGTERM");
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
