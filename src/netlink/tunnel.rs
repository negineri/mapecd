//! ip6tnl トンネル操作（ステップ 6-2）
//!
//! `rtnetlink` 0.14 / `netlink-packet-route` 0.19 に ip6tnl 専用の
//! 高レベル API が存在しないため、`InfoData::Other(raw_bytes)` を使用して
//! IFLA_INFO_DATA を raw NLA 形式でエンコードする。
//!
//! - `get_link_mtu`: RTM_GETLINK で upstream_interface の MTU を取得
//! - `get_link_index`: RTM_GETLINK で ifindex を取得
//! - `create_ip6tnl`: ip6tnl トンネル作成（mode ipip6、encaplimit 0）
//! - `delete_link`: リンク削除

use std::net::Ipv6Addr;

use futures::StreamExt;
use futures::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use netlink_packet_route::{
    link::{InfoData, InfoKind, LinkAttribute, LinkInfo, LinkMessage},
    RouteNetlinkMessage,
};
use rtnetlink::Handle;

use crate::error::MapEError;

// IFLA_IPTUN_* 定数（linux/if_tunnel.h）
const IFLA_IPTUN_LINK: u16 = 1;
const IFLA_IPTUN_LOCAL: u16 = 2;
const IFLA_IPTUN_REMOTE: u16 = 3;
const IFLA_IPTUN_ENCAP_LIMIT: u16 = 6;
const IFLA_IPTUN_PROTO: u16 = 9;

/// IPPROTO_IPIP = 4（IPv4 over IPv6 トンネル、mode ipip6）
const IPPROTO_IPIP: u8 = 4;

/// インターフェース名から現在の MTU を取得する。
///
/// `config.tunnel_mtu` が明示指定されている場合はこの関数をスキップして
/// その値を使用すること（呼び出し元で判断する）。
pub async fn get_link_mtu(handle: &mut Handle, name: &str) -> Result<u32, MapEError> {
    let msg = find_link_by_name(handle, name).await?;
    for attr in &msg.attributes {
        if let LinkAttribute::Mtu(mtu) = attr {
            return Ok(*mtu);
        }
    }
    Err(MapEError::NetlinkError(format!(
        "interface {name}: MTU attribute not found in RTM_GETLINK response"
    )))
}

/// インターフェース名から ifindex を取得する。
pub async fn get_link_index(handle: &mut Handle, name: &str) -> Result<u32, MapEError> {
    let msg = find_link_by_name(handle, name).await?;
    Ok(msg.header.index)
}

/// ip6tnl トンネルを作成し、作成後の ifindex を返す。
///
/// パラメータ:
/// - mode: ipip6 固定（IFLA_IPTUN_PROTO = IPPROTO_IPIP = 4）
/// - encaplimit: 0（RFC 2473 カプセル化深さ制限を無効化）
/// - dev: `link_index`（アンダーレイデバイスを明示）
/// - mtu: 計算済み MTU
///
/// パラメータ変更時は `delete_link` → `create_ip6tnl` の順で再作成すること。
pub async fn create_ip6tnl(
    handle: &mut Handle,
    name: &str,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_index: u32,
    mtu: u32,
) -> Result<u32, MapEError> {
    // ip6tnl INFO_DATA を raw NLA バイト列でエンコード
    let info_data_bytes = encode_ip6tnl_data(local, remote, link_index, 0);

    // LinkMessage を構築
    let mut msg = LinkMessage::default();
    msg.attributes.push(LinkAttribute::IfName(name.to_string()));
    msg.attributes.push(LinkAttribute::Mtu(mtu));
    msg.attributes.push(LinkAttribute::LinkInfo(vec![
        LinkInfo::Kind(InfoKind::Other("ip6tnl".to_string())),
        LinkInfo::Data(InfoData::Other(info_data_bytes)),
    ]));

    // RTM_NEWLINK で作成
    send_newlink(handle, msg).await?;

    // 作成後に RTM_GETLINK で ifindex を取得
    let ifindex = get_link_index(handle, name).await?;

    // トンネルインターフェースを UP 状態にする
    handle
        .link()
        .set(ifindex)
        .up()
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("set link {name} up: {e}")))?;

    Ok(ifindex)
}

/// 指定 ifindex のリンクを削除する。
pub async fn delete_link(handle: &mut Handle, ifindex: u32) -> Result<(), MapEError> {
    handle
        .link()
        .del(ifindex)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("delete link ifindex={ifindex}: {e}")))
}

// ----- 内部ヘルパー -----

/// RTM_GETLINK でインターフェース名に一致する `LinkMessage` を返す。
async fn find_link_by_name(handle: &mut Handle, name: &str) -> Result<LinkMessage, MapEError> {
    let mut stream = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();

    stream
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("get link {name}: {e}")))?
        .ok_or_else(|| MapEError::NetlinkError(format!("interface {name} not found")))
}

/// ip6tnl の IFLA_INFO_DATA を NLA バイト列にエンコードする。
///
/// 各 NLA: `[length: u16 LE][type: u16 LE][value][padding to 4-byte]`
fn encode_ip6tnl_data(
    local: Ipv6Addr,
    remote: Ipv6Addr,
    link_index: u32,
    encaplimit: u8,
) -> Vec<u8> {
    use netlink_packet_utils::{nla::DefaultNla, Emitable};

    let nlas: Vec<DefaultNla> = vec![
        DefaultNla::new(IFLA_IPTUN_LINK, link_index.to_ne_bytes().to_vec()),
        DefaultNla::new(IFLA_IPTUN_LOCAL, local.octets().to_vec()),
        DefaultNla::new(IFLA_IPTUN_REMOTE, remote.octets().to_vec()),
        DefaultNla::new(IFLA_IPTUN_PROTO, vec![IPPROTO_IPIP]),
        DefaultNla::new(IFLA_IPTUN_ENCAP_LIMIT, vec![encaplimit]),
    ];

    let total_len: usize = nlas.iter().map(|n| n.buffer_len()).sum();
    let mut buf = vec![0u8; total_len];
    let mut offset = 0;
    for nla in &nlas {
        nla.emit(&mut buf[offset..]);
        offset += nla.buffer_len();
    }
    buf
}

/// RTM_NEWLINK でリンクを作成する（NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL）。
async fn send_newlink(handle: &mut Handle, msg: LinkMessage) -> Result<(), MapEError> {
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewLink(msg));
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

    let mut response = handle
        .request(req)
        .map_err(|e| MapEError::NetlinkError(format!("RTM_NEWLINK request: {e}")))?;

    while let Some(msg) = response.next().await {
        if let NetlinkPayload::Error(err) = msg.payload {
            return Err(MapEError::NetlinkError(format!(
                "RTM_NEWLINK response error: {err}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::encode_ip6tnl_data;

    /// エンコードされたバイト列の基本構造を検証する。
    #[test]
    fn test_encode_ip6tnl_data_structure() {
        let local: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: std::net::Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        let data = encode_ip6tnl_data(local, remote, 3, 0);

        // 期待するバイト数:
        // IFLA_IPTUN_LINK (u32):   align(4+4) = 8
        // IFLA_IPTUN_LOCAL (IPv6): align(4+16) = 20
        // IFLA_IPTUN_REMOTE (IPv6): align(4+16) = 20
        // IFLA_IPTUN_PROTO (u8):   align(4+1) = 8
        // IFLA_IPTUN_ENCAP_LIMIT (u8): align(4+1) = 8
        // 合計: 8 + 20 + 20 + 8 + 8 = 64
        assert_eq!(data.len(), 64);
    }

    /// IFLA_IPTUN_LINK の type フィールドが 1 であることを確認。
    #[test]
    fn test_encode_link_type_field() {
        let local: std::net::Ipv6Addr = "::".parse().unwrap();
        let remote: std::net::Ipv6Addr = "::".parse().unwrap();
        let data = encode_ip6tnl_data(local, remote, 42, 0);

        // 先頭 NLA は IFLA_IPTUN_LINK = 1
        // [0..1] = length low byte = 8
        // [2..3] = type in LE = [1, 0]
        assert_eq!(data[0], 8, "NLA total length should be 8");
        assert_eq!(data[1], 0);
        assert_eq!(data[2], 1, "NLA type (IFLA_IPTUN_LINK) should be 1");
        assert_eq!(data[3], 0);

        // value: link_index=42 in native byte order
        let link_index = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
        assert_eq!(link_index, 42);
    }

    /// IFLA_IPTUN_PROTO の値が IPPROTO_IPIP = 4 であることを確認。
    #[test]
    fn test_encode_proto_is_ipproto_ipip() {
        let local: std::net::Ipv6Addr = "::".parse().unwrap();
        let remote: std::net::Ipv6Addr = "::".parse().unwrap();
        let data = encode_ip6tnl_data(local, remote, 1, 0);

        // IFLA_IPTUN_PROTO は 4 番目の NLA（offset=8+20+20=48）
        let offset = 48;
        assert_eq!(data[offset + 2], super::IFLA_IPTUN_PROTO as u8);
        assert_eq!(data[offset + 4], super::IPPROTO_IPIP);
    }

    /// IFLA_IPTUN_ENCAP_LIMIT の値が 0 であることを確認。
    #[test]
    fn test_encode_encaplimit_is_zero() {
        let local: std::net::Ipv6Addr = "::".parse().unwrap();
        let remote: std::net::Ipv6Addr = "::".parse().unwrap();
        let data = encode_ip6tnl_data(local, remote, 1, 0);

        // IFLA_IPTUN_ENCAP_LIMIT は 5 番目の NLA（offset=48+8=56）
        let offset = 56;
        assert_eq!(data[offset + 2], super::IFLA_IPTUN_ENCAP_LIMIT as u8);
        assert_eq!(data[offset + 4], 0);
    }

    /// IPv6 アドレスが正しく埋め込まれていることを確認。
    #[test]
    fn test_encode_local_address_bytes() {
        let local: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: std::net::Ipv6Addr = "::".parse().unwrap();
        let data = encode_ip6tnl_data(local, remote, 1, 0);

        // IFLA_IPTUN_LOCAL は 2 番目の NLA（offset=8）
        let offset = 8;
        assert_eq!(data[offset + 2], 2, "NLA type should be IFLA_IPTUN_LOCAL=2");
        let addr_bytes: [u8; 16] = data[offset + 4..offset + 20].try_into().unwrap();
        assert_eq!(std::net::Ipv6Addr::from(addr_bytes), local);
    }
}
