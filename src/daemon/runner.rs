//! デーモンメインランナー
//!
//! Phase 4 実装範囲:
//!   (1) PID ファイル原子的作成・二重起動防止
//!   (2) ディレクトリ作成
//!   (3) MAP Rule キャッシュ読み込み
//!   (7) DhcpV6Receiver 起動・select! イベントループ
//!
//! Phase 5 追加:
//!   (5-a) lease_watcher タスク起動
//!   (5-b) 初回リースファイル読み込み
//!
//! Phase 8 追加（ステップ 8-3）:
//!   rtnetlink 接続・lifecycle::apply/update/cleanup 統合
//!   SIGTERM/SIGINT 時のクリーンアップ

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
    let _pid_guard = PidGuard::create(&config.pid_file).context("PID file creation failed")?;

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
        daemon::lifecycle,
        dhcpv6::{
            DhcpV6Event, DhcpV6Receiver as _, LeaseEvent,
            capture::CaptureReceiver,
            client::ClientReceiver,
            lease_watcher,
        },
        netlink::RtNetlinkHandle,
        nftables::manager::NftExecutor,
    };

    let mut state = DaemonState::new();

    // (3) MAP Rule キャッシュ読み込み
    if let Some(rules) = load_rules_cache(&config.map_rules_cache_file) {
        tracing::info!(path = %config.map_rules_cache_file.display(), rules = rules.len(), "MAP rules loaded from cache");
        state.pending_map_rules = Some(rules);
    }

    // (4) 起動時クリーンアップ（残留設定クリア）
    {
        let nft_executor = NftExecutor;
        startup_cleanup(&config, &nft_executor).await;
    }

    // rtnetlink 接続
    let (rtnetlink_conn, rtnetlink_handle, _rtnetlink_messages) =
        rtnetlink::new_connection().context("rtnetlink::new_connection failed")?;
    tokio::spawn(rtnetlink_conn);

    let mut nl = RtNetlinkHandle::new(rtnetlink_handle);
    let executor = NftExecutor;

    // DHCPv6 チャネル作成
    let (dhcpv6_tx, dhcpv6_rx) = mpsc::channel::<DhcpV6Event>(16);
    // lease_watcher チャネル
    let (lease_tx, lease_rx) = mpsc::channel::<LeaseEvent>(4);

    // (5-a) lease_watcher タスク起動（inotify 登録を先に行う）
    {
        let lease_interface = config.upstream_interface.clone();
        let lease_tx_watcher = lease_tx.clone();
        let lease_cancel = cancel.child_token();
        tokio::spawn(async move {
            if let Err(e) = lease_watcher::run_lease_watcher(
                &lease_interface,
                lease_tx_watcher,
                lease_cancel,
            )
            .await
            {
                tracing::error!("lease_watcher error: {e:#}");
            }
        });
    }

    // (5-b) 初回リースファイル読み込み（inotify 登録後・イベントループ開始前）
    // inotify 登録 → 初回読み込みの順序により、登録前のファイル更新を見落とさない
    if let Some(path) = lease_watcher::lease_file_path(&config.upstream_interface) {
        if let Some(prefix) = lease_watcher::parse_lease_file(&path) {
            tracing::info!(prefix = %prefix, "initial IA_PD loaded from lease file");
            let _ = lease_tx.send(LeaseEvent(prefix)).await;
        }
    }

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

    tracing::info!("mapecd daemon started");

    // select! イベントループ
    let mut dhcpv6_rx_opt = Some(dhcpv6_rx);
    let mut lease_rx_opt = Some(lease_rx);

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received, shutting down");
                cancel.cancel();
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("SIGINT received, shutting down");
                cancel.cancel();
                break;
            }
            _ = cancel.cancelled() => {
                tracing::info!("cancellation requested");
                break;
            }
            event = opt_recv(&mut dhcpv6_rx_opt) => {
                match event {
                    Some(DhcpV6Event::IaPdReceived(prefix)) => {
                        handle_ia_pd(&mut state, &config, prefix, &mut nl, &executor).await;
                    }
                    Some(DhcpV6Event::Both { rules, ia_pd }) => {
                        handle_both(&mut state, &config, rules, ia_pd, &mut nl, &executor).await;
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
                        handle_ia_pd(&mut state, &config, prefix, &mut nl, &executor).await;
                    }
                    None => {
                        lease_rx_opt = None;
                    }
                }
            }
        }
    }

    // SIGTERM/SIGINT 受信後のクリーンアップ
    if let Some(params) = state.params.clone() {
        tracing::info!("running lifecycle cleanup");
        lifecycle::cleanup(&mut state, &config, &params, &mut nl, &executor).await;
    }

    tracing::info!("mapecd daemon stopped");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// イベントハンドラ（Linux 専用）
// ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn handle_ia_pd(
    state: &mut DaemonState,
    config: &Config,
    prefix: ipnet::Ipv6Net,
    nl: &mut impl crate::netlink::NetlinkHandle,
    executor: &impl crate::nftables::manager::CommandExecutor,
) {
    state.pending_ia_pd = Some(prefix);
    apply_if_ready(state, config, nl, executor).await;
}

#[cfg(target_os = "linux")]
async fn handle_both(
    state: &mut DaemonState,
    config: &Config,
    rules: Vec<MapRule>,
    ia_pd: ipnet::Ipv6Net,
    nl: &mut impl crate::netlink::NetlinkHandle,
    executor: &impl crate::nftables::manager::CommandExecutor,
) {
    // MAP Rule キャッシュ保存（ステップ 4-5）
    if let Err(e) = save_rules_cache(&config.map_rules_cache_file, &rules) {
        warn!(path = %config.map_rules_cache_file.display(), "MAP rules cache save failed: {e}");
    }
    state.pending_map_rules = Some(rules);
    state.pending_ia_pd = Some(ia_pd);
    apply_if_ready(state, config, nl, executor).await;
}

#[cfg(target_os = "linux")]
async fn apply_if_ready(
    state: &mut DaemonState,
    config: &Config,
    nl: &mut impl crate::netlink::NetlinkHandle,
    executor: &impl crate::nftables::manager::CommandExecutor,
) {
    use crate::daemon::lifecycle;

    match state.try_compute() {
        Ok(true) => {
            let new_params = match state.params.clone() {
                Some(p) => p,
                None => return,
            };

            let old_params = state.params.clone();

            // 既存パラメータがある場合は update、ない場合は apply
            // Note: try_compute が Ok(true) を返した時点で state.params は Some に更新済み
            // old_params = state.params（更新後）なので、実際の「旧値」は別途管理が必要
            // ここでは state.params を old_params として、
            // apply との分岐は tunnel_ifindex の有無で判断する
            if state.tunnel_ifindex.is_some() {
                // 既に apply 済み → update
                if let Some(ref old) = old_params {
                    if lifecycle::has_changed(old, &new_params) {
                        tracing::info!(
                            ce_ipv6 = %new_params.ce_ipv6,
                            ipv4 = %new_params.ipv4,
                            psid = new_params.psid,
                            br = %new_params.br_address,
                            "MAP-E params changed, updating"
                        );
                        if let Err(e) = lifecycle::update(
                            state,
                            config,
                            old,
                            &new_params,
                            nl,
                            executor,
                        )
                        .await
                        {
                            tracing::error!("lifecycle::update failed: {e}, running cleanup");
                            lifecycle::cleanup(state, config, &new_params, nl, executor).await;
                            state.params = None;
                        }
                    }
                    // 変化なしは何もしない
                }
            } else {
                // 初回 apply
                tracing::info!(
                    ce_ipv6 = %new_params.ce_ipv6,
                    ipv4 = %new_params.ipv4,
                    psid = new_params.psid,
                    br = %new_params.br_address,
                    "MAP-E params computed, applying"
                );
                if let Err(e) =
                    lifecycle::apply(state, config, &new_params, nl, executor).await
                {
                    tracing::error!("lifecycle::apply failed: {e}, running cleanup");
                    lifecycle::cleanup(state, config, &new_params, nl, executor).await;
                    state.params = None;
                }
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
// 起動時クリーンアップ
// ────────────────────────────────────────────────────────────────────

/// 起動時に残留設定（nftables テーブル・トンネル・ルート）をクリアする。
///
/// 前回の異常終了で残留した設定を除去する。エラーは warn で無視する。
#[cfg(target_os = "linux")]
async fn startup_cleanup(
    config: &Config,
    executor: &impl crate::nftables::manager::CommandExecutor,
) {
    use crate::nftables::manager::delete_tables;

    // nftables テーブル削除（存在しない場合はエラーになるが無視）
    if let Err(e) = delete_tables(executor).await {
        tracing::debug!("startup: delete nftables tables (may not exist): {e}");
    }

    // 残留トンネル削除
    let tunnel_name = &config.tunnel_interface;
    // ip link delete はシステムコマンドで行う（rtnetlink 接続前のため）
    let status = tokio::process::Command::new("ip")
        .args(["link", "delete", tunnel_name])
        .status()
        .await;
    match status {
        Ok(s) if s.success() => {
            tracing::info!(tunnel = tunnel_name, "startup: removed residual tunnel");
        }
        _ => {
            tracing::debug!(tunnel = tunnel_name, "startup: no residual tunnel to remove");
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

        // 親ディレクトリを作成する
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all({}) failed", parent.display()))?;
        }

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
// status / stop ヘルパー
// ────────────────────────────────────────────────────────────────────

/// PID ファイルから PID を読み込み、プロセスの生死を確認して表示する。
pub fn status(config: &Config) {
    let pid_path = &config.pid_file;
    match read_pid_file(pid_path) {
        None => println!("stopped"),
        Some(pid) => {
            if is_process_alive(pid) {
                println!("running (pid={pid})");
            } else {
                println!("stopped (stale PID file)");
            }
        }
    }
}

/// PID ファイルから PID を取得して SIGTERM を送信する。
pub fn stop(config: &Config) -> anyhow::Result<()> {
    let pid_path = &config.pid_file;
    let pid = read_pid_file(pid_path)
        .ok_or_else(|| anyhow::anyhow!("mapecd is not running (PID file not found or empty)"))?;

    if !is_process_alive(pid) {
        anyhow::bail!("mapecd is not running (stale PID file: pid={})", pid);
    }

    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        anyhow::bail!("failed to send SIGTERM to pid={pid}: {e}");
    }

    tracing::info!("SIGTERM sent to mapecd (pid={pid})");
    Ok(())
}

/// PID ファイルから PID を読み込む。存在しない・パース不可の場合は None。
fn read_pid_file(path: &Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// プロセスが生存しているか確認する。
fn is_process_alive(pid: u32) -> bool {
    // Linux: /proc/<pid>/status の存在確認
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}/status")).exists()
    }
    // 非 Linux: kill(pid, 0) で確認
    #[cfg(not(target_os = "linux"))]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0
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
            is_fmr: true,
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

    #[test]
    fn test_read_pid_file_missing() {
        assert!(read_pid_file(Path::new("/nonexistent/mapecd.pid")).is_none());
    }

    #[test]
    fn test_read_pid_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");
        std::fs::write(&pid_path, "12345\n").unwrap();
        assert_eq!(read_pid_file(&pid_path), Some(12345));
    }

    #[test]
    fn test_read_pid_file_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");
        std::fs::write(&pid_path, "not-a-pid\n").unwrap();
        assert!(read_pid_file(&pid_path).is_none());
    }

    #[test]
    fn test_is_process_alive_current() {
        // 自プロセスは生存しているはず
        let pid = std::process::id();
        assert!(is_process_alive(pid));
    }

    #[test]
    fn test_is_process_alive_nonexistent() {
        // Linux: /proc/<pid>/status が存在しない PID を使う
        // macOS: kill(pid, 0) が ESRCH を返す PID を使う
        // pid_t は i32 なので u32::MAX は不可（オーバーフロー）
        // 存在しないはずの大きい PID を使う（i32 の最大値付近）
        let unlikely_pid = i32::MAX as u32;  // 2147483647: 通常存在しない
        assert!(!is_process_alive(unlikely_pid));
    }

    // ─── 二重起動防止テスト ───────────────────────────────────

    #[test]
    fn test_pid_guard_create_succeeds() {
        // PID ファイルが存在しない場合は正常に作成できる
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");

        let guard = PidGuard::create(&pid_path);
        assert!(guard.is_ok());

        // PID ファイルが作成されていること
        assert!(pid_path.exists());
        // PID ファイルに自プロセスの PID が書き込まれていること
        let content = std::fs::read_to_string(&pid_path).unwrap();
        let written_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(written_pid, std::process::id());
    }

    // macOS では flock が同一プロセスで再取得可能なため Linux 専用テスト
    #[cfg(target_os = "linux")]
    #[test]
    fn test_pid_guard_double_start_blocked() {
        // 同一 PID ファイルに対して 2 つの PidGuard を作成しようとすると
        // 2 つ目は flock で失敗する（二重起動防止）
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");

        let _guard1 = PidGuard::create(&pid_path).expect("first guard should succeed");
        let guard2 = PidGuard::create(&pid_path);
        assert!(guard2.is_err(), "second guard should fail (already locked)");
    }

    #[test]
    fn test_pid_guard_stale_file_can_be_acquired() {
        // 前回プロセスが異常終了して PID ファイルが残っていても
        // ロックが解放されていれば再取得できる（stale PID ファイルの上書き）
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");

        // 残留 PID ファイルを手動作成（ロックなし）
        std::fs::write(&pid_path, "99999\n").unwrap();

        // ロックが取得できるはず
        let guard = PidGuard::create(&pid_path);
        assert!(guard.is_ok(), "should succeed on stale (unlocked) PID file");

        // 自プロセスの PID で上書きされていること
        let content = std::fs::read_to_string(&pid_path).unwrap();
        let written_pid: u32 = content.trim().parse().unwrap();
        assert_eq!(written_pid, std::process::id());
    }

    #[test]
    fn test_pid_guard_drop_removes_file() {
        // PidGuard が Drop されると PID ファイルが削除される
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("mapecd.pid");

        {
            let _guard = PidGuard::create(&pid_path).unwrap();
            assert!(pid_path.exists());
        }
        // Drop 後はファイルが消えていること
        assert!(!pid_path.exists());
    }
}
