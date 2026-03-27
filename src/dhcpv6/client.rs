//! 独立 DHCPv6 クライアントモード（Linux 専用）
//!
//! Solicit → Advertise → Request → Reply サイクルと
//! Renew/Rebind サイクルを実装する。
//! systemd-networkd 等が既に DHCPv6 を管理している場合は
//! capture モードを使用すること（競合回避）。

use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use dhcproto::{
    v6::{DhcpOption, DhcpOptions, IAPD, Message, MessageType, OptionCode, Status},
    Decodable, Decoder, Encodable, Encoder,
};
use nix::net::if_::if_nametoindex;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::{DhcpV6Event, DhcpV6Receiver};
use crate::{
    config::Config,
    dhcpv6::parser::{parse_ia_pd_info, parse_mape_container},
};

// ────────────────────────────────────────────────────────────────────
// 定数（RFC 3315 Section 5.5）
// ────────────────────────────────────────────────────────────────────

/// Solicit 初回待機時間（秒）
const SOL_TIMEOUT: u64 = 1;
/// Solicit 最大再送間隔（秒）
const SOL_MAX_RT: u64 = 120;
/// Renew 固定再送間隔（秒）
const REN_RETRANS: u64 = 10;
/// Rebind 固定再送間隔初期値（秒）
const REB_RETRANS_INIT: u64 = 10;
/// Rebind 固定再送間隔最大値（秒）
const REB_RETRANS_MAX: u64 = 30;
/// Release タイムアウト（秒）
const RELEASE_TIMEOUT: u64 = 2;

/// RFC 8415 基準時刻（2000-01-01 00:00:00 UTC の Unix タイムスタンプ）
const DUID_LLT_EPOCH: u64 = 946_684_800;

/// DHCPv6 All_DHCP_Relay_Agents_and_Servers マルチキャストアドレス
const ALL_DHCP_RELAY_AGENTS: &str = "[ff02::1:2]:547";

// ────────────────────────────────────────────────────────────────────
// ClientReceiver
// ────────────────────────────────────────────────────────────────────

pub struct ClientReceiver {
    config: Arc<Config>,
}

impl ClientReceiver {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl DhcpV6Receiver for ClientReceiver {
    fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send {
        async move { run_client(*self, tx, cancel).await }
    }
}

// ────────────────────────────────────────────────────────────────────
// メインループ
// ────────────────────────────────────────────────────────────────────

async fn run_client(
    recv: ClientReceiver,
    tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let config = &recv.config;
    let iface = &config.upstream_interface;

    let iaid = get_iaid(iface);
    let duid = load_or_create_duid(config).context("DUID load/create failed")?;
    let socket = create_socket(iface).context("DHCPv6 client socket creation failed")?;

    info!(interface = iface, iaid, "DHCPv6 client started");

    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Solicit → Advertise → Request → Reply
        let lease = match do_initial_exchange(&socket, &duid, iaid, iface, &cancel).await {
            Ok(Some(lease)) => lease,
            Ok(None) => continue, // キャンセル
            Err(e) => {
                warn!("DHCPv6 initial exchange failed: {e:#}");
                // 少し待って再試行
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = cancel.cancelled() => break,
                }
                continue;
            }
        };

        // IA_PD + MAP Rule イベントを送出
        let event = DhcpV6Event::Both {
            rules: lease.rules.clone(),
            ia_pd: lease.prefix,
        };
        if tx.send(event).await.is_err() {
            break;
        }

        // Renew/Rebind サイクル
        let (server_duid, server_unicast) = (lease.server_duid.clone(), lease.server_unicast);
        match do_renewal_loop(
            &socket,
            &duid,
            &server_duid,
            server_unicast,
            iaid,
            iface,
            &lease,
            &tx,
            &cancel,
        )
        .await
        {
            RenewalResult::Expired => {
                info!("DHCPv6 lease expired, restarting Solicit");
                continue;
            }
            RenewalResult::Cancelled => {
                // Release を送信してから終了
                let release_data =
                    build_release(&duid, &server_duid, iaid, lease.ia_pd_for_release);
                if let Ok(data) = release_data {
                    let dst = server_unicast
                        .unwrap_or_else(|| ALL_DHCP_RELAY_AGENTS.parse().unwrap());
                    let _ = tokio::time::timeout(
                        Duration::from_secs(RELEASE_TIMEOUT),
                        socket.send_to(&data, dst),
                    )
                    .await;
                }
                break;
            }
        }
    }

    info!(interface = iface, "DHCPv6 client stopped");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// DHCPv6 交換ロジック
// ────────────────────────────────────────────────────────────────────

struct LeaseInfo {
    prefix: ipnet::Ipv6Net,
    t1: u32,
    t2: u32,
    valid_lifetime: u32,
    rules: Vec<crate::map::rule::MapRule>,
    server_duid: Vec<u8>,
    server_unicast: Option<SocketAddr>,
    /// Release 用に保持する IA_PD オプション
    ia_pd_for_release: IAPD,
}

enum RenewalResult {
    Expired,
    Cancelled,
}

/// Solicit → Advertise → Request → Reply。
/// キャンセル時は Ok(None)。
async fn do_initial_exchange(
    socket: &UdpSocket,
    duid: &[u8],
    iaid: u32,
    iface: &str,
    cancel: &CancellationToken,
) -> anyhow::Result<Option<LeaseInfo>> {
    let oro = build_oro();

    // Solicit 送信 → Advertise 受信（指数バックオフ付き再送）
    let mut rt = SOL_TIMEOUT;
    let xid = new_xid();
    let solicit_data = build_solicit(duid, iaid, xid, &oro)?;

    let adv_msg = loop {
        let dst: SocketAddr = ALL_DHCP_RELAY_AGENTS.parse().unwrap();
        socket.send_to(&solicit_data, dst).await?;
        debug!(interface = iface, "Solicit sent");

        let mut buf = vec![0u8; 4096];
        let result = tokio::select! {
            r = recv_with_timeout(socket, &mut buf, jitter_rt(rt)) => r,
            _ = cancel.cancelled() => return Ok(None),
        };

        match result {
            Ok(Some(n)) => {
                let data = &buf[..n];
                if let Some(msg) = parse_advertise(data, xid) {
                    break msg;
                }
            }
            Ok(None) => {
                // タイムアウト → 再送
                rt = (rt * 2).min(SOL_MAX_RT);
                debug!(interface = iface, rt, "Solicit timeout, retrying");
            }
            Err(e) => return Err(e).context("Solicit recv failed"),
        }
    };

    // Advertise から Server DUID・IA_PD を取得
    let server_duid = extract_server_duid(&adv_msg)
        .context("Advertise missing ServerId")?;
    let ia_pd_from_adv = extract_ia_pd(&adv_msg)
        .context("Advertise missing IA_PD")?;

    // Request 送信 → Reply 受信
    let req_xid = new_xid();
    let request_data = build_request(duid, &server_duid, iaid, req_xid, &ia_pd_from_adv, &oro)?;

    let mut buf = vec![0u8; 4096];
    let reply_msg = loop {
        let dst: SocketAddr = ALL_DHCP_RELAY_AGENTS.parse().unwrap();
        socket.send_to(&request_data, dst).await?;
        debug!(interface = iface, "Request sent");

        let result = tokio::select! {
            r = recv_with_timeout(socket, &mut buf, Duration::from_secs(10)) => r,
            _ = cancel.cancelled() => return Ok(None),
        };

        match result {
            Ok(Some(n)) => {
                let data = &buf[..n];
                if let Some(msg) = parse_reply(data, req_xid) {
                    break msg;
                }
            }
            Ok(None) => {
                // タイムアウト → Request 再送
                debug!(interface = iface, "Request timeout, retrying");
            }
            Err(e) => return Err(e).context("Request recv failed"),
        }
    };

    // Reply を処理して LeaseInfo を構築
    let raw_data = encode_msg(&reply_msg)?;
    process_reply(&raw_data, duid, iaid, server_duid, iface)
        .map(Some)
        .context("Reply processing failed")
}

/// Renew/Rebind サイクル。T1/T2/expire に従いタイマーを駆動する。
#[allow(clippy::too_many_arguments)]
async fn do_renewal_loop(
    socket: &UdpSocket,
    duid: &[u8],
    server_duid: &[u8],
    server_unicast: Option<SocketAddr>,
    iaid: u32,
    iface: &str,
    lease: &LeaseInfo,
    tx: &tokio::sync::mpsc::Sender<DhcpV6Event>,
    cancel: &CancellationToken,
) -> RenewalResult {
    let now = Instant::now();
    let t1_at = now + Duration::from_secs(lease.t1 as u64);
    let t2_at = now + Duration::from_secs(lease.t2 as u64);
    let expire_at = now
        + if lease.valid_lifetime == u32::MAX {
            Duration::from_secs(u64::MAX / 2) // 実質無限大
        } else {
            Duration::from_secs(lease.valid_lifetime as u64)
        };

    let oro = build_oro();

    // T1 まで待機
    tokio::select! {
        _ = tokio::time::sleep_until(t1_at.into()) => {}
        _ = cancel.cancelled() => return RenewalResult::Cancelled,
    }

    // Renew フェーズ（T1 ～ T2）
    let renew_xid = new_xid();
    let mut renew_rt = REN_RETRANS;

    'renew: loop {
        if Instant::now() >= expire_at {
            return RenewalResult::Expired;
        }
        if Instant::now() >= t2_at {
            break 'renew; // Rebind フェーズへ
        }

        let dst = server_unicast
            .unwrap_or_else(|| ALL_DHCP_RELAY_AGENTS.parse().unwrap());

        let renew_data = match build_renew(duid, server_duid, iaid, renew_xid, &ore_ia_pd(lease), &oro) {
            Ok(d) => d,
            Err(e) => { warn!("build_renew failed: {e}"); break 'renew; }
        };
        let _ = socket.send_to(&renew_data, dst).await;
        debug!(interface = iface, "Renew sent");

        let mut buf = vec![0u8; 4096];
        let result = tokio::select! {
            r = recv_with_timeout(socket, &mut buf, Duration::from_secs(renew_rt)) => r,
            _ = tokio::time::sleep_until(t2_at.into()) => { break 'renew; }
            _ = cancel.cancelled() => return RenewalResult::Cancelled,
        };

        match result {
            Ok(Some(n)) => {
                let raw = &buf[..n];
                if let Some(msg) = parse_reply(raw, renew_xid) {
                    let raw_encoded = match encode_msg(&msg) {
                        Ok(d) => d,
                        Err(_) => break 'renew,
                    };
                    match process_reply(&raw_encoded, duid, iaid, server_duid.to_vec(), iface) {
                        Ok(new_lease) => {
                            let event = if !new_lease.rules.is_empty() {
                                DhcpV6Event::Both { rules: new_lease.rules.clone(), ia_pd: new_lease.prefix }
                            } else {
                                DhcpV6Event::IaPdReceived(new_lease.prefix)
                            };
                            let _ = tx.send(event).await;
                            // 新しいリース情報で継続（再帰しない・ここでは単純に戻る）
                            return do_renewal_loop(
                                socket, duid, server_duid, server_unicast,
                                iaid, iface, &new_lease, tx, cancel,
                            )
                            .await;
                        }
                        Err(e) => warn!("Renew Reply processing failed: {e}"),
                    }
                }
            }
            Ok(None) => {
                // タイムアウト、次のループで再送
                debug!(interface = iface, "Renew timeout");
            }
            Err(e) => warn!("Renew recv error: {e}"),
        }
        let _ = renew_rt; // 固定間隔のため更新しない
    }

    // Rebind フェーズ（T2 ～ expire）
    let rebind_xid = new_xid();
    let mut rebind_rt = REB_RETRANS_INIT;

    loop {
        if Instant::now() >= expire_at {
            return RenewalResult::Expired;
        }

        let rebind_data = match build_rebind(duid, iaid, rebind_xid, &ore_ia_pd(lease), &oro) {
            Ok(d) => d,
            Err(e) => { warn!("build_rebind failed: {e}"); return RenewalResult::Expired; }
        };
        let dst: SocketAddr = ALL_DHCP_RELAY_AGENTS.parse().unwrap();
        let _ = socket.send_to(&rebind_data, dst).await;
        debug!(interface = iface, "Rebind sent");

        let mut buf = vec![0u8; 4096];
        let result = tokio::select! {
            r = recv_with_timeout(socket, &mut buf, Duration::from_secs(rebind_rt)) => r,
            _ = tokio::time::sleep_until(expire_at.into()) => return RenewalResult::Expired,
            _ = cancel.cancelled() => return RenewalResult::Cancelled,
        };

        match result {
            Ok(Some(n)) => {
                let raw = &buf[..n];
                if let Some(msg) = parse_reply(raw, rebind_xid) {
                    let raw_encoded = match encode_msg(&msg) {
                        Ok(d) => d,
                        Err(_) => return RenewalResult::Expired,
                    };
                    match process_reply(&raw_encoded, duid, iaid, server_duid.to_vec(), iface) {
                        Ok(new_lease) => {
                            let event = if !new_lease.rules.is_empty() {
                                DhcpV6Event::Both { rules: new_lease.rules.clone(), ia_pd: new_lease.prefix }
                            } else {
                                DhcpV6Event::IaPdReceived(new_lease.prefix)
                            };
                            let _ = tx.send(event).await;
                            return do_renewal_loop(
                                socket, duid, server_duid, server_unicast,
                                iaid, iface, &new_lease, tx, cancel,
                            )
                            .await;
                        }
                        Err(e) => warn!("Rebind Reply processing failed: {e}"),
                    }
                }
            }
            Ok(None) => {
                debug!(interface = iface, "Rebind timeout");
                rebind_rt = rebind_rt.saturating_add(REB_RETRANS_INIT).min(REB_RETRANS_MAX);
            }
            Err(e) => warn!("Rebind recv error: {e}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// メッセージ構築ヘルパー
// ────────────────────────────────────────────────────────────────────

fn new_xid() -> [u8; 3] {
    rand::rng().random()
}

fn build_oro() -> Vec<OptionCode> {
    vec![OptionCode::IAPD, OptionCode::S46ContMape]
}

fn build_solicit(duid: &[u8], iaid: u32, xid: [u8; 3], oro: &[OptionCode]) -> anyhow::Result<Vec<u8>> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ClientId(duid.to_vec().into()));
    opts.insert(DhcpOption::IAPD(IAPD { id: iaid, t1: 0, t2: 0, opts: DhcpOptions::new() }));
    opts.insert(DhcpOption::ORO(oro.to_vec()));

    let msg = Message { msg_type: MessageType::Solicit, xid, opts };
    encode_msg(&msg)
}

fn build_request(
    duid: &[u8],
    server_duid: &[u8],
    iaid: u32,
    xid: [u8; 3],
    ia_pd_from_adv: &IAPD,
    oro: &[OptionCode],
) -> anyhow::Result<Vec<u8>> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ClientId(duid.to_vec().into()));
    opts.insert(DhcpOption::ServerId(server_duid.to_vec().into()));
    opts.insert(DhcpOption::IAPD(ia_pd_from_adv.clone()));
    opts.insert(DhcpOption::ORO(oro.to_vec()));

    let msg = Message { msg_type: MessageType::Request, xid, opts };
    encode_msg(&msg)
}

fn build_renew(
    duid: &[u8],
    server_duid: &[u8],
    iaid: u32,
    xid: [u8; 3],
    ia_pd: &IAPD,
    oro: &[OptionCode],
) -> anyhow::Result<Vec<u8>> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ClientId(duid.to_vec().into()));
    opts.insert(DhcpOption::ServerId(server_duid.to_vec().into()));
    opts.insert(DhcpOption::IAPD(ia_pd.clone()));
    opts.insert(DhcpOption::ORO(oro.to_vec()));

    let msg = Message { msg_type: MessageType::Renew, xid, opts };
    encode_msg(&msg)
}

fn build_rebind(
    duid: &[u8],
    iaid: u32,
    xid: [u8; 3],
    ia_pd: &IAPD,
    oro: &[OptionCode],
) -> anyhow::Result<Vec<u8>> {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ClientId(duid.to_vec().into()));
    // ServerId は含めない（RFC 3315 Section 18.1.4）
    opts.insert(DhcpOption::IAPD(ia_pd.clone()));
    opts.insert(DhcpOption::ORO(oro.to_vec()));

    let msg = Message { msg_type: MessageType::Rebind, xid, opts };
    encode_msg(&msg)
}

fn build_release(
    duid: &[u8],
    server_duid: &[u8],
    iaid: u32,
    ia_pd: IAPD,
) -> anyhow::Result<Vec<u8>> {
    let xid = new_xid();
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ClientId(duid.to_vec().into()));
    opts.insert(DhcpOption::ServerId(server_duid.to_vec().into()));
    opts.insert(DhcpOption::IAPD(ia_pd));

    let msg = Message { msg_type: MessageType::Release, xid, opts };
    encode_msg(&msg)
}

/// LeaseInfo から IA_PD を再構成する（Renew/Rebind 用）
fn ore_ia_pd(lease: &LeaseInfo) -> IAPD {
    lease.ia_pd_for_release.clone()
}

fn encode_msg(msg: &Message) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).context("DHCPv6 message encode failed")?;
    Ok(buf)
}

// ────────────────────────────────────────────────────────────────────
// メッセージ解析ヘルパー
// ────────────────────────────────────────────────────────────────────

/// Advertise を解析して Message を返す。XID 不一致は None。
fn parse_advertise(data: &[u8], xid: [u8; 3]) -> Option<Message> {
    let msg = Message::decode(&mut Decoder::new(data)).ok()?;
    if msg.msg_type() != MessageType::Advertise {
        return None;
    }
    if msg.xid != xid {
        return None;
    }
    // Status Code チェック
    if let Some(DhcpOption::StatusCode(status, _)) = msg.opts().get(OptionCode::StatusCode) {
        if *status != Status::Success {
            return None;
        }
    }
    Some(msg)
}

/// Reply を解析して Message を返す。XID 不一致は None。
fn parse_reply(data: &[u8], xid: [u8; 3]) -> Option<Message> {
    let msg = Message::decode(&mut Decoder::new(data)).ok()?;
    if msg.msg_type() != MessageType::Reply {
        return None;
    }
    if msg.xid != xid {
        return None;
    }
    Some(msg)
}

fn extract_server_duid(msg: &Message) -> Option<Vec<u8>> {
    if let Some(DhcpOption::ServerId(duid)) = msg.opts().get(OptionCode::ServerId) {
        Some(duid.as_ref().to_vec())
    } else {
        None
    }
}

fn extract_ia_pd(msg: &Message) -> Option<IAPD> {
    if let Some(DhcpOption::IAPD(ia_pd)) = msg.opts().get(OptionCode::IAPD) {
        Some(ia_pd.clone())
    } else {
        None
    }
}

/// Reply からリース情報を抽出する。
fn process_reply(
    raw_data: &[u8],
    duid: &[u8],
    iaid: u32,
    server_duid: Vec<u8>,
    iface: &str,
) -> anyhow::Result<LeaseInfo> {
    let msg = Message::decode(&mut Decoder::new(raw_data))
        .context("Reply decode failed")?;

    // トップレベル Status Code
    if let Some(DhcpOption::StatusCode(status, msg_str)) = msg.opts().get(OptionCode::StatusCode) {
        if *status != Status::Success {
            bail!("Reply status code: {:?} ({})", status, msg_str);
        }
    }

    // OPTION_UNICAST チェック
    let server_unicast = if let Some(DhcpOption::Unicast(addr)) = msg.opts().get(OptionCode::Unicast) {
        let sa: SocketAddr = SocketAddrV6::new(*addr, 547, 0, 0).into();
        Some(sa)
    } else {
        None
    };

    // IA_PD パース（iaid 指定）
    let ia_pd_info = parse_ia_pd_info(raw_data, Some(iaid))
        .context("Reply: IA_PD not found or error status")?;

    // MAP Rule パース
    let rules = match parse_mape_container(raw_data) {
        Ok(Some(r)) => r,
        Ok(None) => {
            debug!(interface = iface, "Reply: no S46 container, using cached rules");
            vec![]
        }
        Err(e) => {
            warn!(interface = iface, "Reply: parse_mape_container failed: {e}");
            vec![]
        }
    };

    // IA_PD を Release 用に再構築
    let ia_pd_for_release = IAPD {
        id: iaid,
        t1: ia_pd_info.t1,
        t2: ia_pd_info.t2,
        opts: DhcpOptions::new(),
    };

    Ok(LeaseInfo {
        prefix: ia_pd_info.prefix,
        t1: ia_pd_info.t1,
        t2: ia_pd_info.t2,
        valid_lifetime: ia_pd_info.valid_lifetime,
        rules,
        server_duid,
        server_unicast,
        ia_pd_for_release,
    })
}

// ────────────────────────────────────────────────────────────────────
// ソケット操作ヘルパー
// ────────────────────────────────────────────────────────────────────

fn create_socket(iface: &str) -> anyhow::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("socket create failed")?;
    socket.set_reuse_address(true)?;
    socket
        .bind_device(Some(iface.as_bytes()))
        .with_context(|| format!("bind_device({iface}) failed (SO_BINDTODEVICE requires CAP_NET_RAW)"))?;

    let bind_addr: std::net::SocketAddrV6 =
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 546, 0, 0);
    socket
        .bind(&bind_addr.into())
        .context("bind port 546 failed")?;

    socket.set_nonblocking(true)?;

    // IPV6_MULTICAST_IF でマルチキャスト送出インターフェースを指定
    let ifindex = if_nametoindex(iface)
        .with_context(|| format!("if_nametoindex({iface}) failed"))?;
    let ifindex_u32 = ifindex as libc::c_uint;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_IF,
            &ifindex_u32 as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        );
    }

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("tokio UdpSocket from_std failed")
}

/// タイムアウト付き recv。受信バイト数を返す。タイムアウトは None。
async fn recv_with_timeout(
    socket: &UdpSocket,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> anyhow::Result<Option<usize>> {
    tokio::select! {
        result = socket.recv_from(buf) => {
            let (n, _) = result.context("recv_from failed")?;
            Ok(Some(n))
        }
        _ = tokio::time::sleep(timeout) => Ok(None),
    }
}

// ────────────────────────────────────────────────────────────────────
// DUID 管理
// ────────────────────────────────────────────────────────────────────

fn load_or_create_duid(config: &Config) -> anyhow::Result<Vec<u8>> {
    let path = &config.duid_file;
    if path.exists() {
        let data = std::fs::read(path).context("DUID file read failed")?;
        if data.len() >= 4 {
            return Ok(data);
        }
        warn!("DUID file is too short, regenerating");
    }

    // DUID-LLT 生成
    let mac = get_mac_addr(&config.upstream_interface);
    let time = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (now.saturating_sub(DUID_LLT_EPOCH) & 0xFFFF_FFFF) as u32
    };

    let mut duid = Vec::with_capacity(14);
    duid.extend_from_slice(&1u16.to_be_bytes()); // DUID-LLT type = 1
    duid.extend_from_slice(&1u16.to_be_bytes()); // hardware type = Ethernet = 1
    duid.extend_from_slice(&time.to_be_bytes()); // time
    duid.extend_from_slice(&mac);                // MAC

    // 保存先ディレクトリ作成
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all({}) failed", parent.display()))?;
    }
    std::fs::write(path, &duid)
        .with_context(|| format!("DUID file write failed: {}", path.display()))?;

    info!(path = %path.display(), "DUID-LLT generated and saved");
    Ok(duid)
}

/// upstream_interface の MAC アドレスを取得する。
/// 取得できない場合は全ゼロ MAC を返し warn ログを出力する。
fn get_mac_addr(iface: &str) -> [u8; 6] {
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::SockaddrLike as _;

    if let Ok(addrs) = getifaddrs() {
        for ifaddr in addrs {
            if ifaddr.interface_name != iface {
                continue;
            }
            if let Some(ref addr) = ifaddr.address {
                if let Some(ll) = addr.as_sockaddr_ll() {
                    if ll.sll_halen() == 6 {
                        let raw = ll.sll_addr();
                        return [raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]];
                    }
                }
            }
        }
    }

    warn!(interface = iface, "could not get MAC address, using zero MAC for DUID");
    [0u8; 6]
}

// ────────────────────────────────────────────────────────────────────
// IAID
// ────────────────────────────────────────────────────────────────────

fn get_iaid(iface: &str) -> u32 {
    match if_nametoindex(iface) {
        Ok(idx) => idx,
        Err(e) => {
            warn!(interface = iface, "if_nametoindex failed: {e}, using IAID=0");
            0
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// ジッタ計算（RFC 3315 Section 14）
// ────────────────────────────────────────────────────────────────────

/// RT に ±10% のジッタを加算した Duration を返す。
fn jitter_rt(rt: u64) -> Duration {
    let r: f64 = rand::rng().random(); // [0, 1)
    let factor = 1.0 + (-0.1 + r * 0.2); // [0.9, 1.1)
    Duration::from_secs_f64(rt as f64 * factor)
}
