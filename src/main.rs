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

                    // 権限チェック（ステップ 8-5、Linux 専用）
                    #[cfg(target_os = "linux")]
                    if let Err(e) = check_capabilities(&cfg) {
                        error!("{e}");
                        std::process::exit(1);
                    }

                    // nft・カーネルバージョン確認（ステップ 8-6、Linux 専用）
                    #[cfg(target_os = "linux")]
                    check_nft_and_kernel().await;

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
            match Config::load(&cli.config) {
                Ok(cfg) => runner::status(&cfg),
                Err(e) => {
                    error!("failed to load config: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(Command::Stop) => {
            match Config::load(&cli.config) {
                Ok(cfg) => {
                    if let Err(e) = runner::stop(&cfg) {
                        error!("{e}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    error!("failed to load config: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// 権限チェック（ステップ 8-5、Linux 専用）
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn check_capabilities(cfg: &Config) -> Result<(), String> {
    use mapecd::config::DhcpV6Mode;

    // root (UID=0) の場合は全権限があるためスキップ
    if unsafe { libc::getuid() } == 0 {
        return Ok(());
    }

    // /proc/self/status から CapEff を読み取る
    let caps = read_cap_eff().map_err(|e| format!("failed to read capabilities: {e}"))?;

    const CAP_NET_RAW: u64 = 1 << 13;
    const CAP_NET_ADMIN: u64 = 1 << 12;
    const CAP_NET_BIND_SERVICE: u64 = 1 << 10;

    let mut missing = Vec::new();

    if caps & CAP_NET_RAW == 0 {
        missing.push("CAP_NET_RAW");
    }
    if caps & CAP_NET_ADMIN == 0 {
        missing.push("CAP_NET_ADMIN");
    }
    if cfg.dhcpv6_mode == DhcpV6Mode::Client && caps & CAP_NET_BIND_SERVICE == 0 {
        missing.push("CAP_NET_BIND_SERVICE");
    }

    if !missing.is_empty() {
        return Err(format!(
            "insufficient capabilities: missing {} (run as root or grant capabilities)",
            missing.join(", ")
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn read_cap_eff() -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("read /proc/self/status: {e}"))?;

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(rest.trim(), 16)
                .map_err(|e| format!("parse CapEff: {e}"));
        }
    }

    Err("CapEff not found in /proc/self/status".to_string())
}

// ────────────────────────────────────────────────────────────────────
// nft・カーネルバージョン確認（ステップ 8-6、Linux 専用）
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn check_nft_and_kernel() {
    // nft --version でコマンドの存在確認
    match tokio::process::Command::new("nft")
        .arg("--version")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let ver_str = String::from_utf8_lossy(&output.stdout);
            let ver_str = ver_str.trim();
            tracing::debug!("nft version: {ver_str}");

            // バージョン番号を抽出して 0.9.3 未満なら警告
            if let Some(ver) = parse_nft_version(ver_str) {
                if ver < (0, 9, 3) {
                    tracing::warn!(
                        "nft version {}.{}.{} is older than 0.9.3 (required for 'masquerade to :@port_ranges')",
                        ver.0, ver.1, ver.2
                    );
                }
            }
        }
        Ok(_) => {
            error!("nft command failed; nftables is required for MAP-E operation");
            std::process::exit(1);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            error!("nft command not found; install nftables (>= 0.9.3 required for 'masquerade to :@port_ranges')");
            std::process::exit(1);
        }
        Err(e) => {
            error!("failed to run nft --version: {e}");
            std::process::exit(1);
        }
    }

    // カーネルバージョン確認（Linux 5.14 未満は警告）
    if let Ok(ver_str) = std::fs::read_to_string("/proc/version") {
        if let Some(kver) = parse_kernel_version(&ver_str) {
            if kver < (5, 14, 0) {
                tracing::warn!(
                    "kernel {}.{}.{} is older than 5.14 (required for 'masquerade to :@port_ranges')",
                    kver.0, kver.1, kver.2
                );
            }
        }
    }
}

/// `nft vX.Y.Z (...)` 形式からバージョンタプルを抽出する。
#[cfg(target_os = "linux")]
fn parse_nft_version(ver_str: &str) -> Option<(u32, u32, u32)> {
    // "nftables v0.9.3 (Topsy)" のような形式
    let token = ver_str.split_whitespace().find(|t| t.starts_with('v'))?;
    let digits: &str = token.trim_start_matches('v');
    parse_version_triple(digits)
}

/// `/proc/version` の文字列から Linux カーネルバージョンを抽出する。
#[cfg(target_os = "linux")]
fn parse_kernel_version(ver_str: &str) -> Option<(u32, u32, u32)> {
    // "Linux version 5.15.0-..." のような形式
    let mut iter = ver_str.split_whitespace();
    // "Linux" "version" の次がバージョン番号
    while let Some(token) = iter.next() {
        if token == "version" {
            if let Some(ver) = iter.next() {
                return parse_version_triple(ver);
            }
        }
    }
    None
}

/// "X.Y.Z..." 形式から (X, Y, Z) タプルを抽出する。
#[cfg(target_os = "linux")]
fn parse_version_triple(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.splitn(4, '.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    // patch 部分はハイフンや文字が混じる場合がある ("0-generic" など)
    let patch_str = parts.next().unwrap_or("0");
    let patch = patch_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse::<u32>()
        .unwrap_or(0);
    Some((major, minor, patch))
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_nft_version_standard() {
        let s = "nftables v0.9.3 (Topsy)";
        assert_eq!(parse_nft_version(s), Some((0, 9, 3)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_nft_version_newer() {
        let s = "nftables v1.0.7 (Old Doc Yak #3)";
        assert_eq!(parse_nft_version(s), Some((1, 0, 7)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_kernel_version() {
        let s = "Linux version 5.15.0-91-generic (buildd@...) #101-Ubuntu SMP...";
        assert_eq!(parse_kernel_version(s), Some((5, 15, 0)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_kernel_version_old() {
        let s = "Linux version 5.10.0-23-amd64 #1 SMP...";
        assert_eq!(parse_kernel_version(s), Some((5, 10, 0)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nft_version_comparison() {
        assert!(Some((0, 9, 3)) >= Some((0, 9, 3)));
        assert!(Some((0, 9, 2)) < Some((0, 9, 3)));
        assert!(Some((1, 0, 0)) > Some((0, 9, 3)));
    }
}
