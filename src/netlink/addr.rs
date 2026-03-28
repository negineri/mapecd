//! CE アドレス付与・削除（ステップ 6-1）
//!
//! - `add_ce_ipv6_addr` / `del_ce_ipv6_addr`: upstream_interface に /128 を付与・削除
//! - `add_ce_ipv4_addr` / `del_ce_ipv4_addr`: tunnel_interface に /32 を付与・削除

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    AddressFamily,
};
use rtnetlink::Handle;

use crate::error::MapEError;

/// upstream_interface に CE IPv6 アドレス（/128）を付与する。
pub async fn add_ipv6_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError> {
    handle
        .address()
        .add(ifindex, IpAddr::V6(addr), 128)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("add IPv6 addr {addr}/128: {e}")))
}

/// upstream_interface から CE IPv6 アドレス（/128）を削除する。
pub async fn del_ipv6_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv6Addr,
) -> Result<(), MapEError> {
    let mut msg = AddressMessage::default();
    msg.header.family = AddressFamily::Inet6;
    msg.header.prefix_len = 128;
    msg.header.index = ifindex;
    msg.attributes.push(AddressAttribute::Address(IpAddr::V6(addr)));

    handle
        .address()
        .del(msg)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("del IPv6 addr {addr}/128: {e}")))
}

/// tunnel_interface に CE IPv4 アドレス（/32）を付与する。
///
/// トンネル作成後に呼び出すこと（デバイスが存在している必要がある）。
pub async fn add_ipv4_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError> {
    handle
        .address()
        .add(ifindex, IpAddr::V4(addr), 32)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("add IPv4 addr {addr}/32: {e}")))
}

/// tunnel_interface から CE IPv4 アドレス（/32）を削除する。
///
/// トンネル削除と同時に消滅するが、`cleanup` の統一性のため明示的に呼び出す。
/// ENODEV（デバイス消滅済み）は warn ログで無視する。
pub async fn del_ipv4_addr(
    handle: &Handle,
    ifindex: u32,
    addr: Ipv4Addr,
) -> Result<(), MapEError> {
    let mut msg = AddressMessage::default();
    msg.header.family = AddressFamily::Inet;
    msg.header.prefix_len = 32;
    msg.header.index = ifindex;
    msg.attributes.push(AddressAttribute::Address(IpAddr::V4(addr)));
    msg.attributes
        .push(AddressAttribute::Local(IpAddr::V4(addr)));

    match handle.address().del(msg).execute().await {
        Ok(()) => Ok(()),
        Err(rtnetlink::Error::NetlinkError(ref nl_err))
            if nl_err.to_string().contains("No such device")
                || nl_err.to_string().contains("(os error 19)") =>
        {
            tracing::warn!("del IPv4 addr {addr}/32: device already gone, skipping");
            Ok(())
        }
        Err(e) => Err(MapEError::NetlinkError(format!("del IPv4 addr {addr}/32: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        error::MapEError,
        netlink::NetlinkHandle,
    };

    /// テスト用 mock。addr 操作を記録する。
    struct MockHandle {
        pub added_v6: Vec<(u32, Ipv6Addr)>,
        pub deleted_v6: Vec<(u32, Ipv6Addr)>,
        pub added_v4: Vec<(u32, Ipv4Addr)>,
        pub deleted_v4: Vec<(u32, Ipv4Addr)>,
        /// `del_ipv4_addr` で "no such device" を返すかどうか
        pub simulate_nodev: bool,
    }

    impl MockHandle {
        fn new() -> Self {
            Self {
                added_v6: vec![],
                deleted_v6: vec![],
                added_v4: vec![],
                deleted_v4: vec![],
                simulate_nodev: false,
            }
        }
    }

    impl NetlinkHandle for MockHandle {
        async fn add_ipv6_addr(
            &mut self,
            ifindex: u32,
            addr: Ipv6Addr,
        ) -> Result<(), MapEError> {
            self.added_v6.push((ifindex, addr));
            Ok(())
        }

        async fn del_ipv6_addr(
            &mut self,
            ifindex: u32,
            addr: Ipv6Addr,
        ) -> Result<(), MapEError> {
            self.deleted_v6.push((ifindex, addr));
            Ok(())
        }

        async fn add_ipv4_addr(
            &mut self,
            ifindex: u32,
            addr: Ipv4Addr,
        ) -> Result<(), MapEError> {
            self.added_v4.push((ifindex, addr));
            Ok(())
        }

        async fn del_ipv4_addr(
            &mut self,
            ifindex: u32,
            addr: Ipv4Addr,
        ) -> Result<(), MapEError> {
            if self.simulate_nodev {
                return Ok(());
            }
            self.deleted_v4.push((ifindex, addr));
            Ok(())
        }

        async fn get_link_mtu(&mut self, _name: &str) -> Result<u32, MapEError> {
            Ok(1500)
        }

        async fn get_link_index(&mut self, _name: &str) -> Result<u32, MapEError> {
            Ok(1)
        }

        async fn create_ip6tnl(
            &mut self,
            _name: &str,
            _local: Ipv6Addr,
            _remote: Ipv6Addr,
            _link_index: u32,
            _mtu: u32,
        ) -> Result<u32, MapEError> {
            Ok(10)
        }

        async fn delete_link(&mut self, _ifindex: u32) -> Result<(), MapEError> {
            Ok(())
        }

        async fn get_ipv4_default_routes(&mut self) -> Result<Vec<u32>, MapEError> {
            Ok(vec![])
        }

        async fn add_ipv4_default_route(&mut self, _oif: u32) -> Result<(), MapEError> {
            Ok(())
        }

        async fn del_ipv4_default_route_by_oif(&mut self, _oif: u32) -> Result<(), MapEError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_mock_add_ipv6_addr() {
        let mut mock = MockHandle::new();
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        mock.add_ipv6_addr(3, addr).await.unwrap();
        assert_eq!(mock.added_v6, vec![(3, addr)]);
    }

    #[tokio::test]
    async fn test_mock_del_ipv6_addr() {
        let mut mock = MockHandle::new();
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        mock.del_ipv6_addr(3, addr).await.unwrap();
        assert_eq!(mock.deleted_v6, vec![(3, addr)]);
    }

    #[tokio::test]
    async fn test_mock_add_ipv4_addr() {
        let mut mock = MockHandle::new();
        let addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        mock.add_ipv4_addr(10, addr).await.unwrap();
        assert_eq!(mock.added_v4, vec![(10, addr)]);
    }

    #[tokio::test]
    async fn test_mock_del_ipv4_addr_nodev_ignored() {
        let mut mock = MockHandle::new();
        mock.simulate_nodev = true;
        let addr: Ipv4Addr = "192.0.2.1".parse().unwrap();
        // ENODEV は Ok(()) として扱われること
        assert!(mock.del_ipv4_addr(10, addr).await.is_ok());
        assert!(mock.deleted_v4.is_empty());
    }
}
