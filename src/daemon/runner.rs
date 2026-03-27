//! デーモンメインランナー（Phase 4 スタブ）
//!
//! Phase 4 実装範囲:
//!   (1) PID ファイル原子的作成・二重起動防止
//!   (2) ディレクトリ作成
//!   (3) MAP Rule キャッシュ読み込み
//!   (7) DhcpV6Receiver 起動・select! イベントループ
//!
//! Phase 5/6 以降で lease_watcher・apply/update が追加される。

use std::{
    io::Write as _,
    path::Path,
    sync::Arc,
};

use anyhow::Context as _;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{config::Config, map::rule::MapRule};

#[cfg(target_os = "linux")]
use crate::{daemon::state::DaemonState, error::MapEError};

// ────────────────────────────────────────────────────────────────────
// エントリポイント
// ────────────────────────────────────────────────────────────────────

/// デーモンを起動する。
///
/// Linux 以外のプラットフォームではエラーを返す。
pub async fn start(config: Arc<Config>, cancel: CancellationToken) -> anyhow::Result<()> {
    // ディレクトリ作成（/run/mapecd/, /var/lib/mapecd/）
    setup_dirs(&config)?;

    // PID ファイル作成・二重起動防止
    let pid_path = Path::new("/run/mapecd/mapecd.pid");
    let _pid_guard = PidGuard::create(pid_path).context("PID file creation failed")?;

    #[cfg(target_os = "linux")]
    return start_linux(config, cancel).await;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cancel;
        tracing::error!("MAP-E daemon は Linux 専用です");
        Err(anyhow::anyhow!("MAP-E daemon requires Linux"))
    }
}

// ────────────────────────────────────────────────────────────────────
// Linux 専用メインループ
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn start_linux(config: Arc<Config>, cancel: CancellationToken) -> anyhow::Result<()> {
    use tokio::sync::mpsc;
    use tokio::signal::unix::{SignalKind, signal};

    use crate::{
        config::DhcpV6Mode,
        dhcpv6::{DhcpV6Receiver as _, LeaseEvent, capture::CaptureReceiver, client::ClientReceiver},
    };

    let mut state = DaemonState::new();

    // (3) MAP Rule キャッシュ読み込み
    if let Some(rules) = load_rules_cache(&config.map_rules_cache_file) {
        info!(path = %config.map_rules_cache_file.display(), rules = rules.len(), "MAP rules loaded from cache");
        state.pending_map_rules = Some(rules);
    }

    // DHCPv6 チャネル作成
    let (dhcpv6_tx, dhcpv6_rx) = mpsc::channel::<DhcpV6Event>(16);
    // lease_watcher チャネル（Phase 5 で watcher を起動する）
    let (_lease_tx, lease_rx) = mpsc::channel::<LeaseEvent>(4);

    // (7) DhcpV6Receiver 起動
    let child_cancel = cancel.child_token();
    match config.dhcpv6_mode {
        DhcpV6Mode::Capture => {
            let receiver = CaptureReceiver::new(config.upstream_interface.clone());
            tokio::spawn(async move {
                if let Err(e) = Box::new(receiver).run(dhcpv6_tx, child_cancel).await {
                    tracing::error!("DHCPv6 capture error: {e:#}");
                }
            });
        }
        DhcpV6Mode::Client => {
            let receiver = ClientReceiver::new(config.clone());
            tokio::spawn(async move {
                if let Err(e) = Box::new(receiver).run(dhcpv6_tx, child_cancel).await {
                    tracing::error!("DHCPv6 client error: {e:#}");
                }
            });
        }
    }

    // シグナルハンドラ設定
    let mut sigterm = signal(SignalKind::terminate()).context("SIGTERM handler setup failed")?;
    let mut sigint = signal(SignalKind::interrupt()).context("SIGINT handler setup failed")?;

    info!("mapecd daemon started");

    // select! イベントループ
    let mut dhcpv6_rx_opt = Some(dhcpv6_rx);
    let mut lease_rx_opt = Some(lease_rx);

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down");
                cancel.cancel();
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received, shutting down");
                cancel.cancel();
                break;
            }
            _ = cancel.cancelled() => {
                info!("cancellation requested");
                break;
            }
            event = opt_recv(&mut dhcpv6_rx_opt) => {
                match event {
                    Some(DhcpV6Event::IaPdReceived(prefix)) => {
                        handle_ia_pd(&mut state, prefix);
                    }
                    Some(DhcpV6Event::Both { rules, ia_pd }) => {
                        handle_both(&mut state, rules, ia_pd, &config);
                    }
                    None => {
                        warn!("DHCPv6 receiver channel closed");
                        dhcpv6_rx_opt = None;
                    }
                }
            }
            event = opt_recv(&mut lease_rx_opt) => {
                match event {
                    Some(LeaseEvent(prefix)) => {
                        handle_ia_pd(&mut state, prefix);
                    }
                    None => {
                        lease_rx_opt = None;
                    }
                }
            }
        }
    }

    info!("mapecd daemon stopped");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// イベントハンドラ（Linux 専用）
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn handle_ia_pd(state: &mut DaemonState, prefix: ipnet::Ipv6Net) {
    state.pending_ia_pd = Some(prefix);
    apply_if_ready(state);
}

#[cfg(target_os = "linux")]
fn handle_both(
    state: &mut DaemonState,
    rules: Vec<MapRule>,
    ia_pd: ipnet::Ipv6Net,
    config: &Config,
) {
    // MAP Rule キャッシュ保存（ステップ 4-5）
    if let Err(e) = save_rules_cache(&config.map_rules_cache_file, &rules) {
        warn!(path = %config.map_rules_cache_file.display(), "MAP rules cache save failed: {e}");
    }
    state.pending_map_rules = Some(rules);
    state.pending_ia_pd = Some(ia_pd);
    apply_if_ready(state);
}

#[cfg(target_os = "linux")]
fn apply_if_ready(state: &mut DaemonState) {
    match state.try_compute() {
        Ok(true) => {
            if let Some(ref p) = state.params {
                tracing::info!(
                    ce_ipv6 = %p.ce_ipv6,
                    ipv4 = %p.ipv4,
                    psid = p.psid,
                    br = %p.br_address,
                    "MAP-E params computed"
                    // TODO Phase 6: apply/update
                );
            }
        }
        Ok(false) => {} // 情報不足
        Err(MapEError::NoPrefixMatch) => {
            warn!(
                ia_pd = ?state.pending_ia_pd,
                "no MAP rule matches CE prefix"
            );
        }
        Err(e) => {
            tracing::error!("compute_mape_params failed: {e}");
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// キャッシュ読み書き（純粋関数、単体テスト対象）
// ────────────────────────────────────────────────────────────────────

/// MAP Rule キャッシュファイルを読み込む。
/// ファイルが存在しない・パースエラーの場合は None を返す。
pub fn load_rules_cache(path: &Path) -> Option<Vec<MapRule>> {
    let data = std::fs::read(path).ok()?;
    let rules: Vec<MapRule> = serde_json::from_slice(&data)
        .map_err(|e| warn!(path = %path.display(), "MAP rules cache parse failed: {e}"))
        .ok()?;
    Some(rules)
}

/// MAP Rule キャッシュファイルに書き込む。
pub fn save_rules_cache(path: &Path, rules: &[MapRule]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all({}) failed", parent.display()))?;
    }
    let data = serde_json::to_vec(rules).context("MAP rules JSON serialize failed")?;
    // 原子的書き込み: 一時ファイル → rename
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &data)
        .with_context(|| format!("write({}) failed", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("rename to {} failed", path.display()))?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// セットアップヘルパー
// ────────────────────────────────────────────────────────────────────

fn setup_dirs(config: &Config) -> anyhow::Result<()> {
    for dir in [
        Path::new("/run/mapecd"),
        Path::new("/var/lib/mapecd"),
        config
            .map_rules_cache_file
            .parent()
            .unwrap_or(Path::new("/run/mapecd")),
        config.duid_file.parent().unwrap_or(Path::new("/var/lib/mapecd")),
    ] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create_dir_all({}) failed", dir.display()))?;
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// PID ファイル管理
// ────────────────────────────────────────────────────────────────────

/// PID ファイルを保持するガード型。Drop 時にファイルを削除する。
struct PidGuard {
    path: std::path::PathBuf,
}

impl PidGuard {
    /// PID ファイルを原子的に作成する。
    /// flock で排他ロックを取得できない場合は二重起動とみなしてエラーを返す。
    fn create(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::io::AsRawFd as _;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open PID file {} failed", path.display()))?;

        // LOCK_EX | LOCK_NB: 排他ロック、ブロックしない
        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let e = std::io::Error::last_os_error();
            anyhow::bail!("mapecd is already running (PID file locked: {}): {e}", path.display());
        }

        file.set_len(0)?;
        write!(file, "{}\n", std::process::id())?;

        Ok(Self { path: path.to_path_buf() })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ────────────────────────────────────────────────────────────────────
// select! ヘルパー
// ────────────────────────────────────────────────────────────────────

/// `Option<Receiver<T>>` から非同期で受信する。
/// None の場合は永遠に Pending を返す（select! ブランチを無効化）。
#[cfg(target_os = "linux")]
async fn opt_recv<T>(rx: &mut Option<tokio::sync::mpsc::Receiver<T>>) -> Option<T> {
    match rx {
        Some(inner) => inner.recv().await,
        None => std::future::pending().await,
    }
}

// ────────────────────────────────────────────────────────────────────
// テスト
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;
    use crate::map::rule::{MapRule, PortParams};

    fn make_rule() -> MapRule {
        MapRule {
            ipv6_prefix: "2001:db8::/32".parse().unwrap(),
            ipv4_prefix: "192.0.2.0/24".parse().unwrap(),
            ea_length: 40,
            is_fme: true,
            br_address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            port_params: PortParams { psid_offset: 4, psid_length: 8 },
        }
    }

    #[test]
    fn test_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("rules.cache");

        let rules = vec![make_rule()];
        save_rules_cache(&cache_path, &rules).unwrap();

        let loaded = load_rules_cache(&cache_path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].ea_length, 40);
        assert_eq!(loaded[0].port_params.psid_offset, 4);
    }

    #[test]
    fn test_load_nonexistent_cache() {
        let result = load_rules_cache(Path::new("/nonexistent/rules.cache"));
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("rules.cache");

        let rules1 = vec![make_rule()];
        save_rules_cache(&cache_path, &rules1).unwrap();

        let mut rule2 = make_rule();
        rule2.ea_length = 48;
        save_rules_cache(&cache_path, &[rule2]).unwrap();

        let loaded = load_rules_cache(&cache_path).unwrap();
        assert_eq!(loaded[0].ea_length, 48);
    }
}
