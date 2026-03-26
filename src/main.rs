mod cli;
mod config;
mod error;

use clap::Parser;
use tracing::error;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(&cli.log_level);

    match &cli.command {
        Some(Command::Start) | None => {
            match config::Config::load(&cli.config) {
                Ok(cfg) => {
                    tracing::info!(
                        upstream = %cfg.upstream_interface,
                        tunnel = %cfg.tunnel_interface,
                        "config loaded"
                    );
                    // TODO: Phase 4 以降でデーモンループを実装
                    tracing::info!("mapecd starting (not yet implemented)");
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

    let filter = EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

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
