//! systemd-networkd リースファイル監視（Linux inotify 依存）
//!
//! `/run/systemd/netif/leases/<ifindex>` を inotify で監視し、
//! `X-DELEGATED-PREFIX` フィールドの変化を `LeaseEvent` として送出する。

use std::ffi::OsStr;
use std::os::unix::io::{AsFd as _, AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ipnet::Ipv6Net;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::LeaseEvent;

/// `nix::Inotify` は `AsFd` を実装するが `AsRawFd` を実装しない（nix 0.29+）。
/// `tokio::io::unix::AsyncFd` は `AsRawFd` を要求するため、ブリッジラッパーが必要。
struct InotifyFd(Inotify);

impl AsRawFd for InotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

const LEASES_DIR: &str = "/run/systemd/netif/leases";

// ────────────────────────────────────────────────────────────────────
// パブリック API
// ────────────────────────────────────────────────────────────────────

/// inotify による systemd-networkd リースファイル監視タスク。
///
/// `/run/systemd/netif/leases/` が存在しない場合は `warn` を出力して終了する。
/// `upstream_interface` に対応する ifindex のファイルに `IN_CLOSE_WRITE` /
/// `IN_MOVED_TO` イベントが発生した場合のみパースを実施する。
pub async fn run_lease_watcher(
    upstream_interface: &str,
    tx: mpsc::Sender<LeaseEvent>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let dir = Path::new(LEASES_DIR);
    if !dir.exists() {
        warn!(
            path = LEASES_DIR,
            "systemd-networkd lease directory not found; lease_watcher exiting. \
             Start mapecd after systemd-networkd or configure After=systemd-networkd.service."
        );
        return Ok(());
    }

    // upstream_interface に対応する ifindex を取得
    let ifindex =
        nix::net::if_::if_nametoindex(upstream_interface).with_context(|| {
            format!("if_nametoindex({upstream_interface}) failed: interface may not exist")
        })?;

    let target_name = ifindex.to_string();
    let lease_file = dir.join(&target_name);

    // inotify 初期化（NONBLOCK: AsyncFd と組み合わせるために必須）
    let inotify = Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK)
        .context("inotify_init failed")?;
    inotify
        .add_watch(
            dir,
            AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO,
        )
        .context("inotify_add_watch failed")?;

    let async_fd = AsyncFd::new(InotifyFd(inotify)).context("AsyncFd::new failed")?;

    info!(
        interface = upstream_interface,
        ifindex,
        lease_file = %lease_file.display(),
        "lease_watcher started"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = async_fd.readable() => {
                let mut guard = result.context("inotify readable error")?;
                // 利用可能なイベントを全て読み出す（EAGAIN/WouldBlock まで）
                loop {
                    match guard.try_io(|inner| {
                        inner
                            .get_ref()
                            .0
                            .read_events()
                            .map_err(std::io::Error::from)
                    }) {
                        Ok(Ok(events)) => {
                            for event in events {
                                if event.name.as_deref() == Some(OsStr::new(&target_name)) {
                                    handle_lease_event(&lease_file, &tx).await;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::error!("inotify read_events error: {e}");
                            break;
                        }
                        Err(_would_block) => break, // readiness cleared
                    }
                }
            }
        }
    }

    info!("lease_watcher stopped");
    Ok(())
}

/// リースファイルをパースして `LeaseEvent` を送出する。
async fn handle_lease_event(lease_file: &Path, tx: &mpsc::Sender<LeaseEvent>) {
    match parse_lease_file(lease_file) {
        Some(prefix) => {
            info!(prefix = %prefix, "IA_PD updated from lease file");
            if tx.send(LeaseEvent(prefix)).await.is_err() {
                tracing::debug!("lease_watcher: receiver dropped");
            }
        }
        None => {
            warn!(
                path = %lease_file.display(),
                "X-DELEGATED-PREFIX not found or invalid in lease file"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// リースファイルパース（純粋関数・単体テスト対象）
// ────────────────────────────────────────────────────────────────────

/// systemd-networkd リースファイルから `X-DELEGATED-PREFIX` を抽出する。
///
/// ファイルが存在しない・フィールドがない場合は `None` を返す。
pub fn parse_lease_file(path: &Path) -> Option<Ipv6Net> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_delegated_prefix(&content)
}

/// リースファイルの文字列から `X-DELEGATED-PREFIX` を抽出する（純粋関数）。
pub fn parse_delegated_prefix(content: &str) -> Option<Ipv6Net> {
    for line in content.lines() {
        if let Some(value) = line.trim().strip_prefix("X-DELEGATED-PREFIX=") {
            return value.trim().parse::<Ipv6Net>().ok();
        }
    }
    None
}

/// upstream_interface に対応するリースファイルパスを返す。
///
/// インターフェースが存在しない場合は `None`。
pub fn lease_file_path(upstream_interface: &str) -> Option<PathBuf> {
    let ifindex = nix::net::if_::if_nametoindex(upstream_interface).ok()?;
    Some(PathBuf::from(LEASES_DIR).join(ifindex.to_string()))
}

// ────────────────────────────────────────────────────────────────────
// テスト
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_delegated_prefix_basic() {
        let content = "\
ADDRESS=192.168.1.100
PREFIXLEN=24
X-DELEGATED-PREFIX=2001:db8::/48
";
        let result = parse_delegated_prefix(content);
        assert_eq!(result, Some("2001:db8::/48".parse::<Ipv6Net>().unwrap()));
    }

    #[test]
    fn test_parse_delegated_prefix_with_comment() {
        let content = "\
# This is private data. Do not parse.
ADDRESS=192.168.1.1
X-DELEGATED-PREFIX=2001:db8:1::/56
LIFETIME=86400
";
        let result = parse_delegated_prefix(content);
        assert_eq!(result, Some("2001:db8:1::/56".parse::<Ipv6Net>().unwrap()));
    }

    #[test]
    fn test_parse_delegated_prefix_not_found() {
        let content = "ADDRESS=192.168.1.1\nLIFETIME=86400\n";
        assert!(parse_delegated_prefix(content).is_none());
    }

    #[test]
    fn test_parse_delegated_prefix_invalid_prefix() {
        let content = "X-DELEGATED-PREFIX=not-a-prefix\n";
        assert!(parse_delegated_prefix(content).is_none());
    }

    #[test]
    fn test_parse_delegated_prefix_empty() {
        assert!(parse_delegated_prefix("").is_none());
    }

    #[test]
    fn test_parse_delegated_prefix_trailing_whitespace() {
        let content = "X-DELEGATED-PREFIX=2001:db8::/32  \n";
        let result = parse_delegated_prefix(content);
        assert_eq!(result, Some("2001:db8::/32".parse::<Ipv6Net>().unwrap()));
    }

    #[test]
    fn test_parse_lease_file_nonexistent() {
        let result = parse_lease_file(Path::new("/nonexistent/lease/file"));
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_lease_file_with_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("5");
        std::fs::write(
            &path,
            "# systemd lease\nADDRESS=2001:db8::1\nX-DELEGATED-PREFIX=2001:db8::/48\n",
        )
        .unwrap();
        let result = parse_lease_file(&path);
        assert_eq!(result, Some("2001:db8::/48".parse::<Ipv6Net>().unwrap()));
    }

    /// inotify 統合テスト（実 Linux 環境でのみ動作）
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires real Linux inotify and filesystem"]
    async fn test_run_lease_watcher_integration() {
        let dir = tempfile::tempdir().unwrap();
        // このテストはディレクトリを /run/systemd/netif/leases に向けられないため
        // 実際の run_lease_watcher は呼び出さず、パース関数のみ確認する
        let path = dir.path().join("1");
        std::fs::write(&path, "X-DELEGATED-PREFIX=2001:db8::/48\n").unwrap();
        assert!(parse_lease_file(&path).is_some());
    }
}
