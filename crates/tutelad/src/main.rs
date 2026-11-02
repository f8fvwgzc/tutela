//! The `tutelad` binary. See the library for what it does.

use std::process::ExitCode;

use clap::Parser;

/// The Tutela service.
#[derive(Debug, Parser)]
#[command(name = "tutelad", version, about)]
struct Args {}

#[tokio::main]
async fn main() -> ExitCode {
    Args::parse();
    // Every Tutela binary installs the one crypto provider itself.
    if tutela_safenet::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("tutelad: a crypto provider is already installed");
        return ExitCode::FAILURE;
    }
    let config = match tutelad::Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tutelad: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = tutelad::telemetry::init_logs(&config.log) {
        eprintln!("tutelad: {e:#}");
        return ExitCode::FAILURE;
    }
    match tutelad::run(config, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "tutelad failed");
            ExitCode::FAILURE
        }
    }
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
