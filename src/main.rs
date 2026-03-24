mod cli;
mod config;
mod dhcpv6;
mod error;
mod mape;
mod netlink;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    cli.run().await
}
