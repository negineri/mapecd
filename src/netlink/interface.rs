use std::net::Ipv6Addr;

use futures::TryStreamExt;
use ipnet::Ipv6Net;
use rtnetlink::Handle;
use tracing::{debug, info};

use super::NetlinkError;

/// NIC に IPv6 アドレスを割り当てる
pub async fn assign_ipv6_address(
    handle: &Handle,
    interface: &str,
    address: Ipv6Net,
) -> Result<(), NetlinkError> {
    let if_index = get_interface_index(handle, interface).await?;

    info!("IPv6 アドレスを割り当てます: {} → {}", interface, address);

    handle
        .address()
        .add(if_index, address.addr().into(), address.prefix_len())
        .execute()
        .await
        .map_err(|e| NetlinkError::AddressConfig(e.to_string()))?;

    Ok(())
}

/// インターフェースを UP にする
pub async fn set_link_up(handle: &Handle, interface: &str) -> Result<(), NetlinkError> {
    let if_index = get_interface_index(handle, interface).await?;

    debug!("インターフェースを UP にします: {}", interface);

    handle
        .link()
        .set(if_index)
        .up()
        .execute()
        .await
        .map_err(|e| NetlinkError::Connection(e.to_string()))?;

    Ok(())
}

/// MTU を設定する
pub async fn set_mtu(
    handle: &Handle,
    interface: &str,
    mtu: u32,
) -> Result<(), NetlinkError> {
    let if_index = get_interface_index(handle, interface).await?;

    debug!("MTU を設定します: {} → {}", interface, mtu);

    handle
        .link()
        .set(if_index)
        .mtu(mtu)
        .execute()
        .await
        .map_err(|e| NetlinkError::Connection(e.to_string()))?;

    Ok(())
}

/// インターフェース名からインデックスを取得する
pub async fn get_interface_index(
    handle: &Handle,
    interface: &str,
) -> Result<u32, NetlinkError> {
    let mut links = handle.link().get().match_name(interface.to_string()).execute();

    if let Some(link) = links
        .try_next()
        .await
        .map_err(|e| NetlinkError::Connection(e.to_string()))?
    {
        Ok(link.header.index)
    } else {
        Err(NetlinkError::InterfaceNotFound(interface.to_string()))
    }
}
