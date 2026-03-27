pub mod parser;

#[cfg(target_os = "linux")]
pub mod capture;
#[cfg(target_os = "linux")]
pub mod client;

use ipnet::Ipv6Net;

use crate::map::rule::MapRule;

// ────────────────────────────────────────────────────────────────────
// イベント型
// ────────────────────────────────────────────────────────────────────

/// `DhcpV6Receiver` が送出するイベント。
pub enum DhcpV6Event {
    /// IA_PD のみ更新（OPTION_S46_CONT_MAPE なし Reply）。
    IaPdReceived(Ipv6Net),
    /// MAP Rule + IA_PD 両方更新（通常の DHCPv6 Reply）。
    Both {
        rules: Vec<MapRule>,
        ia_pd: Ipv6Net,
    },
}

/// `lease_watcher` タスクが送出するイベント。IA_PD のみを運ぶ専用型。
///
/// `DhcpV6Event` と型を分けることで `lease_rx` チャネルには IA_PD 以外を
/// 送出できないことをコンパイル時に保証する。
pub struct LeaseEvent(pub Ipv6Net);

// ────────────────────────────────────────────────────────────────────
// DhcpV6Receiver トレイト（Linux 専用）
// ────────────────────────────────────────────────────────────────────

/// DHCPv6 パケット受信タスクの共通インターフェース。
///
/// `runner.rs` は `match config.dhcpv6_mode` で具体型を選択して
/// 直接 `tokio::spawn` する。`dyn DhcpV6Receiver` は使用しない
///（RPITIT は object-safe でないため）。
#[cfg(target_os = "linux")]
pub trait DhcpV6Receiver: Send {
    fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

// ────────────────────────────────────────────────────────────────────
// テスト用 MockReceiver（上位レイヤのテストに使用）
// ────────────────────────────────────────────────────────────────────

/// テスト用モック DhcpV6Receiver。
///
/// 事前に指定したイベントを順番に送出して終了する。
/// `runner.rs` 等の上位レイヤのテストで `DhcpV6Receiver` の代わりに使用する。
#[cfg(all(test, target_os = "linux"))]
pub struct MockReceiver {
    pub events: Vec<DhcpV6Event>,
}

#[cfg(all(test, target_os = "linux"))]
impl DhcpV6Receiver for MockReceiver {
    fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send {
        async move {
            for event in self.events {
                if cancel.is_cancelled() {
                    break;
                }
                // チャネルが閉じられた場合は終了
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            Ok(())
        }
    }
}
