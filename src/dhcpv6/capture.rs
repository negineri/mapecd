//! AF_PACKET パッシブキャプチャモード（Linux 専用）
//!
//! upstream_interface 上の DHCPv6 Reply（UDP dport=546）をパッシブに
//! スニッフィングし、MAP Rule と IA_PD を取得する。
//! T1/T2 タイマー管理は不要。

use std::{
    net::Ipv6Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

use anyhow::Context as _;
use dhcproto::v6::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::Decodable;
use dhcproto::Decoder;
use nix::net::if_::if_nametoindex;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{DhcpV6Event, DhcpV6Receiver};
use crate::dhcpv6::parser::{parse_ia_pd, parse_mape_container};

// ────────────────────────────────────────────────────────────────────
// BPF フィルタ: Ethernet II, IPv6, UDP dport=546
// ────────────────────────────────────────────────────────────────────
//
// フレームレイアウト（Ethernet II）:
//   [0..13]  Ethernet ヘッダ (14 bytes)
//   [12..13] ethertype (0x86DD = IPv6)
//   [14..53] IPv6 ヘッダ (40 bytes)
//   [20]     next header (17 = UDP)
//   [38..53] destination IPv6 address
//   [54..61] UDP ヘッダ (8 bytes)
//   [56..57] UDP dport
//   [62..]   DHCPv6 ペイロード
//
// BPF オフセット計算:
//   ethertype at [12], next_header at [20], udp_dport at [56]

static BPF_FILTER: [libc::sock_filter; 8] = [
    // ldh [12] ; ethertype
    libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 12 },
    // jeq 0x86DD, jt=0 (next), jf=5 (ret 0)
    libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 0x86DD },
    // ldb [20] ; IPv6 next header
    libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 20 },
    // jeq 17 (UDP), jt=0 (next), jf=3 (ret 0)
    libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 17 },
    // ldh [56] ; UDP dport
    libc::sock_filter { code: 0x28, jt: 0, jf: 0, k: 56 },
    // jeq 546 (DHCPv6 client port), jt=0 (next), jf=1 (ret 0)
    libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: 546 },
    // ret 65535 ; accept
    libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 65535 },
    // ret 0 ; reject
    libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 },
];

// ────────────────────────────────────────────────────────────────────
// CaptureReceiver
// ────────────────────────────────────────────────────────────────────

pub struct CaptureReceiver {
    pub upstream_interface: String,
}

impl CaptureReceiver {
    pub fn new(upstream_interface: String) -> Self {
        Self { upstream_interface }
    }
}

impl DhcpV6Receiver for CaptureReceiver {
    fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send {
        async move { run_capture(*self, tx, cancel).await }
    }
}

async fn run_capture(
    recv: CaptureReceiver,
    tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let iface = &recv.upstream_interface;

    // AF_PACKET SOCK_RAW ソケット作成
    let sockfd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            // ETH_P_IPV6 をネットワークバイトオーダーに変換して proto として渡す
            (libc::ETH_P_IPV6 as u16).to_be() as libc::c_int,
        )
    };
    if sockfd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("AF_PACKET socket creation failed (CAP_NET_RAW required)");
    }

    // ノンブロッキング設定
    if unsafe { libc::fcntl(sockfd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        unsafe { libc::close(sockfd) };
        return Err(std::io::Error::last_os_error()).context("fcntl O_NONBLOCK failed");
    }

    // ifindex 取得
    let ifindex = if_nametoindex(iface.as_str())
        .with_context(|| format!("if_nametoindex({iface}) failed"))?;

    // sockaddr_ll を構成して bind
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IPV6 as u16).to_be();
    sll.sll_ifindex = ifindex as i32;

    if unsafe {
        libc::bind(
            sockfd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } < 0
    {
        unsafe { libc::close(sockfd) };
        return Err(std::io::Error::last_os_error())
            .context("bind AF_PACKET failed");
    }

    // BPF フィルタを SO_ATTACH_FILTER でアタッチ
    // prog は *mut sock_filter を含み Send でないため、ブロックスコープで await 前に drop する
    {
        let prog = libc::sock_fprog {
            len: BPF_FILTER.len() as u16,
            filter: BPF_FILTER.as_ptr() as *mut libc::sock_filter,
        };
        if unsafe {
            libc::setsockopt(
                sockfd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const libc::sock_fprog as *const libc::c_void,
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        } < 0
        {
            unsafe { libc::close(sockfd) };
            return Err(std::io::Error::last_os_error()).context("SO_ATTACH_FILTER failed");
        }
        // ブロック終了時に prog が drop される
    }

    // OwnedFd でラップして AsyncFd に渡す（fd の所有権を移動）
    let owned_fd = unsafe { OwnedFd::from_raw_fd(sockfd) };
    let async_fd = AsyncFd::new(owned_fd).context("AsyncFd creation failed")?;

    tracing::info!(interface = iface, "DHCPv6 capture started");

    // 受信ループの冒頭で一度だけリンクローカルアドレスを取得し、以後再利用する。
    // None の場合は次のパケット受信時に再取得を試みる。
    let mut our_ll_addr: Option<Ipv6Addr> = get_link_local_addr(iface);
    if our_ll_addr.is_none() {
        warn!(interface = iface, "link-local address not found, will retry on each packet");
    }

    let mut buf = vec![0u8; 65536];

    loop {
        // AsyncFd readable を CancellationToken と競合させる
        let n = tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("DHCPv6 capture cancelled");
                return Ok(());
            }
            guard = async_fd.readable() => {
                let mut guard = guard.context("AsyncFd readable error")?;
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::recv(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(n as usize)
                    }
                }) {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        tracing::warn!("recv error: {e}");
                        continue;
                    }
                    Err(_would_block) => continue,
                }
            }
        };

        let frame = &buf[..n];

        // リンクローカルアドレスが未取得の場合は再試行
        if our_ll_addr.is_none() {
            our_ll_addr = get_link_local_addr(iface);
        }

        if let Err(e) = process_frame(frame, &our_ll_addr, iface, &tx).await {
            debug!("frame processing error: {e}");
        }
    }
}

/// 受信フレームを宛先 IPv6 アドレスでフィルタリングする（純粋関数）。
///
/// # 動作
///
/// - `our_ll_addr` が `Some(addr)` の場合:
///   - 宛先が `addr` と一致する → `true`（処理する）
///   - 宛先がマルチキャスト（`ff00::/8`）→ `true`（処理する）
///   - それ以外のユニキャスト → `false`（スキップ）
/// - `our_ll_addr` が `None` の場合:
///   - 常に `true`（リンクローカルアドレス未取得時はチェックをスキップして全パケットを処理）
/// - フレームが宛先 IPv6 を含む長さ未満の場合: `false`
pub(crate) fn passes_dst_filter(frame: &[u8], our_ll_addr: &Option<Ipv6Addr>) -> bool {
    // 宛先 IPv6 アドレスは Ethernet ヘッダ (14) + IPv6 dst offset (24) = 38 バイト目から 16 バイト
    if frame.len() < 54 {
        return false;
    }
    let ll = match our_ll_addr {
        None => return true, // アドレス未取得 → フィルタスキップ → 全パケット処理
        Some(addr) => addr,
    };
    let Ok(octets) = <[u8; 16]>::try_from(&frame[38..54]) else {
        return false;
    };
    let dst_ip = Ipv6Addr::from(octets);
    let is_multicast = dst_ip.octets()[0] == 0xff;
    is_multicast || dst_ip == *ll
}

/// 受信フレームを処理して DhcpV6Event を送出する。
async fn process_frame(
    frame: &[u8],
    our_ll_addr: &Option<Ipv6Addr>,
    iface: &str,
    tx: &tokio::sync::mpsc::Sender<DhcpV6Event>,
) -> anyhow::Result<()> {
    // 最小フレーム長確認（Ethernet + IPv6 + UDP + DHCPv6 最小1バイト）
    if frame.len() < 63 {
        return Ok(());
    }

    // 宛先 IPv6 アドレスフィルタリング（他ホスト宛て Reply の誤処理防止）
    if !passes_dst_filter(frame, our_ll_addr) {
        return Ok(());
    }

    // DHCPv6 ペイロード（Ethernet 14 + IPv6 40 + UDP 8 = 62 バイト目から）
    let dhcp_payload = &frame[62..];

    // msg-type == 7 (Reply) チェック
    if dhcp_payload.is_empty() || dhcp_payload[0] != 7 {
        return Ok(());
    }

    // dhcproto でデコードしてトップレベル Status Code を確認
    let msg = Message::decode(&mut Decoder::new(dhcp_payload))
        .context("DHCPv6 message decode failed")?;

    if msg.msg_type() != MessageType::Reply {
        return Ok(());
    }

    // トップレベル Status Code が Success 以外 → スキップ
    if let Some(DhcpOption::StatusCode(sc)) = msg.opts().get(OptionCode::StatusCode) {
        use dhcproto::v6::Status;
        if sc.status != Status::Success {
            warn!(interface = iface, status = ?sc.status, msg = sc.msg, "DHCPv6 Reply non-success status");
            return Ok(());
        }
    }

    // IA_PD をパース
    let Some(ia_pd_prefix) = parse_ia_pd(dhcp_payload, None) else {
        // IA_PD を含まない Reply（Confirm への Reply 等） → スキップ
        return Ok(());
    };

    // OPTION_S46_CONT_MAPE をパース
    match parse_mape_container(dhcp_payload) {
        Ok(Some(rules)) => {
            debug!(interface = iface, prefix = %ia_pd_prefix, rules = rules.len(), "DHCPv6 Reply with MAP rules");
            let _ = tx.send(DhcpV6Event::Both { rules, ia_pd: ia_pd_prefix }).await;
        }
        Ok(None) => {
            // S46 コンテナなし → IaPdReceived のみ
            debug!(interface = iface, prefix = %ia_pd_prefix, "DHCPv6 Reply without MAP rules");
            let _ = tx.send(DhcpV6Event::IaPdReceived(ia_pd_prefix)).await;
        }
        Err(e) => {
            warn!(interface = iface, "parse_mape_container failed: {e}");
            // IA_PD はあるので IaPdReceived は送出する
            let _ = tx.send(DhcpV6Event::IaPdReceived(ia_pd_prefix)).await;
        }
    }

    Ok(())
}

/// upstream_interface のリンクローカルアドレス（fe80::/10）を取得する。
///
/// 受信ループ冒頭で一度だけ呼び出し、変数に保持して再利用する。
/// None の場合（インターフェース未 UP・RA 未受信等）は次のパケット受信時に再試行する。
fn get_link_local_addr(iface: &str) -> Option<Ipv6Addr> {
    use nix::ifaddrs::getifaddrs;

    let addrs = getifaddrs().ok()?;
    for ifaddr in addrs {
        if ifaddr.interface_name != iface {
            continue;
        }
        let addr = ifaddr.address.as_ref()?;
        // nix 0.29: SockAddr::as_sockaddr_in6() → Option<&SockaddrIn6>
        if let Some(sin6) = addr.as_sockaddr_in6() {
            let ip = sin6.ip();
            let octets = ip.octets();
            // fe80::/10: 先頭バイト 0xFE、2 バイト目上位 2 ビット = 0b10
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return Some(ip);
            }
        }
    }
    None
}

// ────────────────────────────────────────────────────────────────────
// テスト
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 宛先 IPv6 アドレスを指定した最小フレームを作成する（63 バイト）。
    /// Ethernet(14) + IPv6(40) + UDP(8) + DHCPv6(1 バイト)
    fn make_frame_with_dst(dst: &[u8; 16]) -> Vec<u8> {
        let mut frame = vec![0u8; 63];
        frame[38..54].copy_from_slice(dst);
        frame
    }

    // ── 一致時のみイベント送出（宛先 == リンクローカルアドレス）──────────

    #[test]
    fn test_filter_dst_match_passes() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let frame = make_frame_with_dst(&ll.octets());
        assert!(passes_dst_filter(&frame, &Some(ll)));
    }

    // ── 不一致時スキップ（ユニキャスト・他ホスト宛て）────────────────────

    #[test]
    fn test_filter_dst_mismatch_unicast_skipped() {
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 5, 6, 7, 8);
        let frame = make_frame_with_dst(&other.octets());
        assert!(!passes_dst_filter(&frame, &Some(ll)));
    }

    // ── マルチキャスト宛ては自アドレスと一致しなくても処理する ────────────

    #[test]
    fn test_filter_multicast_passes_regardless_of_ll() {
        // ff02::1:2 = All_DHCP_Relay_Agents_and_Servers
        let multicast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x0002);
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        let frame = make_frame_with_dst(&multicast.octets());
        assert!(passes_dst_filter(&frame, &Some(ll)));
    }

    // ── アドレス取得失敗時はチェックをスキップして全パケットを処理 ─────────

    #[test]
    fn test_filter_no_ll_addr_passes_all() {
        let unicast = Ipv6Addr::new(0xfe80, 0, 0, 0, 9, 9, 9, 9);
        let frame = make_frame_with_dst(&unicast.octets());
        // our_ll_addr = None → フィルタスキップ → true
        assert!(passes_dst_filter(&frame, &None));
    }

    // ── フレームが短すぎる場合は false ────────────────────────────────

    #[test]
    fn test_filter_short_frame_rejected() {
        let frame = vec![0u8; 30]; // 宛先アドレス領域 [38..54] に届かない
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4);
        assert!(!passes_dst_filter(&frame, &Some(ll)));
        // our_ll_addr = None でも short frame は false
        assert!(!passes_dst_filter(&frame, &None));
    }
}
