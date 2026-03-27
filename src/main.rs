mod cli;

use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::cli::{Cli, Command};
use mapecd::{config::Config, daemon::runner};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(&cli.log_level);

    let cancel = CancellationToken::new();

    match &cli.command {
        Some(Command::Start) | None => {
            match Config::load(&cli.config) {
                Ok(cfg) => {
                    tracing::info!(
                        upstream = %cfg.upstream_interface,
                        tunnel = %cfg.tunnel_interface,
                        mode = ?cfg.dhcpv6_mode,
                        "config loaded"
                    );
                    if let Err(e) = runner::start(Arc::new(cfg), cancel).await {
                        error!("daemon error: {e:#}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    error!("failed to load config: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(Command::Status) => {
            // TODO: Phase 4 以降で実装
            println!("status: not yet implemented");
        }
        Some(Command::Stop) => {
            // TODO: Phase 4 以降で実装
            println!("stop: not yet implemented");
        }
    }
}

fn init_logging(log_level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/run/systemd/journal/socket").exists() {
            if let Ok(layer) = tracing_journald::layer() {
                use tracing_subscriber::prelude::*;
                tracing_subscriber::registry()
                    .with(filter)
                    .with(layer)
                    .init();
                return;
            }
        }
    }

    fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
}
