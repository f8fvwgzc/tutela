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
