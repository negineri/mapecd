use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use rtnetlink::Handle;
use tracing::info;

use super::NetlinkError;

/// IPv4 デフォルトルートをトンネルインターフェース経由に設定する
///
/// 相当するコマンド: `ip route add default dev mape0`
pub async fn add_default_route_via_tunnel(
    handle: &Handle,
    tunnel_interface: &str,
) -> Result<(), NetlinkError> {
    use crate::netlink::interface::get_interface_index;

    let if_index = get_interface_index(handle, tunnel_interface).await?;

    info!(
        "IPv4 デフォルトルートを設定します: default via {}",
        tunnel_interface
    );

    handle
        .route()
        .add()
        .v4()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(if_index)
        .execute()
        .await
        .map_err(|e| NetlinkError::RouteConfig(e.to_string()))?;

    Ok(())
}

/// IPv4 デフォルトルートを削除する
pub async fn del_default_route(handle: &Handle, tunnel_interface: &str) -> Result<(), NetlinkError> {
    use crate::netlink::interface::get_interface_index;

    let if_index = get_interface_index(handle, tunnel_interface).await?;

    info!("IPv4 デフォルトルートを削除します");

    handle
        .route()
        .del()
        .v4()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(if_index)
        .execute()
        .await
        .map_err(|e| NetlinkError::RouteConfig(e.to_string()))?;

    Ok(())
}

/// ISP への IPv6 ルートを設定する
pub async fn add_ipv6_route(
    handle: &Handle,
    prefix: Ipv6Net,
    interface: &str,
) -> Result<(), NetlinkError> {
    use crate::netlink::interface::get_interface_index;

    let if_index = get_interface_index(handle, interface).await?;

    info!("IPv6 ルートを設定します: {} dev {}", prefix, interface);

    handle
        .route()
        .add()
        .v6()
        .destination_prefix(prefix.network(), prefix.prefix_len())
        .output_interface(if_index)
        .execute()
        .await
        .map_err(|e| NetlinkError::RouteConfig(e.to_string()))?;

    Ok(())
}
