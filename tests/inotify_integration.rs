#![cfg(target_os = "linux")]

use std::time::Duration;

use mapecd::dhcpv6::LeaseEvent;
use mapecd::dhcpv6::lease_watcher::run_lease_watcher;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// `run_lease_watcher` が IN_CLOSE_WRITE イベントを検知して
/// `LeaseEvent` を送出することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_inotify_close_write_delivers_lease_event() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    // lo インターフェースの ifindex は Network Namespace 内でも常に 1
    let lease_file = dir.path().join("1");

    // 初期ファイルを作成する（X-DELEGATED-PREFIX なし）
    std::fs::write(&lease_file, "ADDRESS=192.168.1.1\n").expect("write initial lease failed");

    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(4);

    let dir_path = dir.path().to_path_buf();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        run_lease_watcher("lo", &dir_path, tx, cancel_clone).await
    });

    // watcher の起動を待つ
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ファイルを更新して X-DELEGATED-PREFIX を追加する
    std::fs::write(
        &lease_file,
        "ADDRESS=192.168.1.1\nX-DELEGATED-PREFIX=2001:db8::/48\n",
    )
    .expect("write updated lease failed");

    // イベントを受信する（最大 2 秒）
    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(result.is_ok(), "inotify event not received within 2s");
    let LeaseEvent(prefix) = result.unwrap().expect("channel closed unexpectedly");
    assert_eq!(prefix.prefix_len(), 48);

    cancel.cancel();
    handle.await.expect("task panicked").expect("task failed");
}

/// `run_lease_watcher` が IN_MOVED_TO イベント（atomic write）を検知して
/// `LeaseEvent` を送出することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_inotify_moved_to_delivers_lease_event() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let lease_file = dir.path().join("1");

    // 初期ファイルを作成する
    std::fs::write(&lease_file, "ADDRESS=192.168.1.1\n").expect("write initial lease failed");

    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(4);

    let dir_path = dir.path().to_path_buf();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        run_lease_watcher("lo", &dir_path, tx, cancel_clone).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // atomic write で rename（IN_MOVED_TO）をシミュレートする
    let tmp = dir.path().join(".tmp_lease");
    std::fs::write(
        &tmp,
        "ADDRESS=192.168.1.1\nX-DELEGATED-PREFIX=2001:db8:1::/56\n",
    )
    .expect("write tmp lease failed");
    std::fs::rename(&tmp, &lease_file).expect("rename failed");

    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(result.is_ok(), "inotify IN_MOVED_TO event not received within 2s");
    let LeaseEvent(prefix) = result.unwrap().expect("channel closed unexpectedly");
    assert_eq!(prefix.prefix_len(), 56);

    cancel.cancel();
    handle.await.expect("task panicked").expect("task failed");
}
