use std::net::{Ipv4Addr, Ipv6Addr};

use rtnetlink::Handle;
use tracing::info;

use super::NetlinkError;

/// MAP-E トンネルの設定パラメータ
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// トンネルインターフェース名
    pub name: String,
    /// CE の IPv6 アドレス（ローカル側）
    pub local: Ipv6Addr,
    /// BR の IPv6 アドレス（リモート側）
    pub remote: Ipv6Addr,
    /// MAP-E MTU（通常 1460）
    pub mtu: u32,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            name: "mape0".to_string(),
            local: Ipv6Addr::UNSPECIFIED,
            remote: Ipv6Addr::UNSPECIFIED,
            mtu: 1460,
        }
    }
}

/// ip6tnl トンネルインターフェースを作成する
///
/// 相当するコマンド: `ip tunnel add mape0 mode ip4ip6 local <local> remote <remote>`
pub async fn create_ip6tnl(
    handle: &Handle,
    config: &TunnelConfig,
) -> Result<(), NetlinkError> {
    info!(
        "ip6tnl トンネルを作成します: {} (local={}, remote={})",
        config.name, config.local, config.remote
    );

    // TODO: rtnetlink の ip6tnl 作成 API を使用
    // rtnetlink クレートのバージョンによって API が異なるため要確認

    Err(NetlinkError::TunnelConfig(
        "ip6tnl 作成は未実装です".to_string(),
    ))
}

/// トンネルインターフェースを削除する
pub async fn delete_tunnel(handle: &Handle, name: &str) -> Result<(), NetlinkError> {
    use crate::netlink::interface::get_interface_index;

    info!("トンネルインターフェースを削除します: {}", name);

    let if_index = get_interface_index(handle, name).await?;

    handle
        .link()
        .del(if_index)
        .execute()
        .await
        .map_err(|e| NetlinkError::TunnelConfig(e.to_string()))?;

    Ok(())
}
