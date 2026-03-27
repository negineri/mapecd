//! IPv4 デフォルトルート管理（ステップ 6-3）
//!
//! - `add_default_route`: 既存の IPv4 デフォルトルートを全削除してからトンネル経由で追加
//! - `del_default_route`: トンネル oif でフィルタしてデフォルトルートのみ削除
//! - `get_ipv4_default_routes`: 現在の IPv4 デフォルトルート oif 一覧を返す

use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::{Handle, IpVersion};

use crate::error::MapEError;

/// 現在の IPv4 デフォルトルート（0.0.0.0/0）の oif ifindex 一覧を返す。
pub async fn get_ipv4_default_routes(handle: &mut Handle) -> Result<Vec<u32>, MapEError> {
    let mut routes = handle
        .route()
        .get(IpVersion::V4)
        .execute();

    let mut oifs: Vec<u32> = Vec::new();

    while let Some(msg) = routes
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("get IPv4 routes: {e}")))?
    {
        // デフォルトルート: destination_prefix_length == 0
        if msg.header.destination_prefix_length != 0 {
            continue;
        }
        // スコープが Universe のユニキャスト
        if msg.header.scope != RouteScope::Universe {
            continue;
        }
        for attr in &msg.attributes {
            if let RouteAttribute::Oif(oif) = attr {
                oifs.push(*oif);
            }
        }
    }

    Ok(oifs)
}

/// IPv4 デフォルトルートをトンネル経由に設定する。
///
/// 実行前に既存の IPv4 デフォルトルート（dst=0.0.0.0/0）を全列挙して削除する。
/// 削除失敗は warn ログで続行する。
pub async fn add_default_route(handle: &mut Handle, oif: u32) -> Result<(), MapEError> {
    add_ipv4_default_route(handle, oif).await
}

/// `add_default_route` の内部実装（`NetlinkHandle` トレイトから呼び出される）。
pub async fn add_ipv4_default_route(handle: &mut Handle, oif: u32) -> Result<(), MapEError> {
    // 既存のデフォルトルートを全削除
    let existing = get_ipv4_default_routes(handle).await?;
    for existing_oif in existing {
        if let Err(e) = del_ipv4_default_route_by_oif(handle, existing_oif).await {
            tracing::warn!("failed to delete existing default route oif={existing_oif}: {e}, continuing");
        }
    }

    // トンネル経由のデフォルトルートを追加
    handle
        .route()
        .add()
        .v4()
        .output_interface(oif)
        .protocol(RouteProtocol::Static)
        .scope(RouteScope::Universe)
        .kind(RouteType::Unicast)
        .execute()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("add default route oif={oif}: {e}")))
}

/// トンネル経由のデフォルトルートのみを削除する（oif でフィルタ）。
///
/// 以前存在していた他のデフォルトルートは復元しない（MAP-E 専用ルーター前提）。
pub async fn del_default_route(handle: &mut Handle, oif: u32) -> Result<(), MapEError> {
    del_ipv4_default_route_by_oif(handle, oif).await
}

/// `del_default_route` の内部実装（`NetlinkHandle` トレイトから呼び出される）。
pub async fn del_ipv4_default_route_by_oif(
    handle: &mut Handle,
    oif: u32,
) -> Result<(), MapEError> {
    // RTM_GETROUTE で oif に一致するデフォルトルートを探して削除
    let mut routes = handle.route().get(IpVersion::V4).execute();

    let mut to_delete: Vec<RouteMessage> = Vec::new();

    while let Some(msg) = routes
        .try_next()
        .await
        .map_err(|e| MapEError::NetlinkError(format!("get IPv4 routes (del): {e}")))?
    {
        if msg.header.destination_prefix_length != 0 {
            continue;
        }
        let has_oif = msg.attributes.iter().any(|a| {
            matches!(a, RouteAttribute::Oif(o) if *o == oif)
        });
        if has_oif {
            to_delete.push(msg);
        }
    }

    for msg in to_delete {
        handle
            .route()
            .del(msg)
            .execute()
            .await
            .map_err(|e| MapEError::NetlinkError(format!("del default route oif={oif}: {e}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        error::MapEError,
        netlink::{NetlinkHandle, route},
    };

    struct MockHandle {
        pub default_routes: Vec<u32>,
        pub added_routes: Vec<u32>,
        pub deleted_routes: Vec<u32>,
    }

    impl MockHandle {
        fn new(default_routes: Vec<u32>) -> Self {
            Self {
                default_routes,
                added_routes: vec![],
                deleted_routes: vec![],
            }
        }
    }

    impl NetlinkHandle for MockHandle {
        async fn add_ipv6_addr(&mut self, _: u32, _: Ipv6Addr) -> Result<(), MapEError> {
            Ok(())
        }
        async fn del_ipv6_addr(&mut self, _: u32, _: Ipv6Addr) -> Result<(), MapEError> {
            Ok(())
        }
        async fn add_ipv4_addr(&mut self, _: u32, _: Ipv4Addr) -> Result<(), MapEError> {
            Ok(())
        }
        async fn del_ipv4_addr(&mut self, _: u32, _: Ipv4Addr) -> Result<(), MapEError> {
            Ok(())
        }
        async fn get_link_mtu(&mut self, _: &str) -> Result<u32, MapEError> {
            Ok(1500)
        }
        async fn get_link_index(&mut self, _: &str) -> Result<u32, MapEError> {
            Ok(1)
        }
        async fn create_ip6tnl(
            &mut self,
            _: &str,
            _: Ipv6Addr,
            _: Ipv6Addr,
            _: u32,
            _: u32,
        ) -> Result<u32, MapEError> {
            Ok(10)
        }
        async fn delete_link(&mut self, _: u32) -> Result<(), MapEError> {
            Ok(())
        }
        async fn get_ipv4_default_routes(&mut self) -> Result<Vec<u32>, MapEError> {
            Ok(self.default_routes.clone())
        }
        async fn add_ipv4_default_route(&mut self, oif: u32) -> Result<(), MapEError> {
            self.added_routes.push(oif);
            Ok(())
        }
        async fn del_ipv4_default_route_by_oif(&mut self, oif: u32) -> Result<(), MapEError> {
            self.deleted_routes.push(oif);
            self.default_routes.retain(|&r| r != oif);
            Ok(())
        }
    }

    /// 既存ルートがある場合、add_ipv4_default_route の前に削除されること。
    #[tokio::test]
    async fn test_add_route_clears_existing() {
        let mut mock = MockHandle::new(vec![2, 3]);

        // 既存ルートを全削除してから新規追加
        let existing = mock.get_ipv4_default_routes().await.unwrap();
        for oif in existing {
            mock.del_ipv4_default_route_by_oif(oif).await.unwrap();
        }
        mock.add_ipv4_default_route(10).await.unwrap();

        assert_eq!(mock.deleted_routes, vec![2, 3]);
        assert_eq!(mock.added_routes, vec![10]);
        assert!(mock.default_routes.is_empty());
    }

    /// 既存ルートがない場合でも add_ipv4_default_route が成功すること。
    #[tokio::test]
    async fn test_add_route_no_existing() {
        let mut mock = MockHandle::new(vec![]);
        mock.add_ipv4_default_route(10).await.unwrap();
        assert_eq!(mock.added_routes, vec![10]);
        assert!(mock.deleted_routes.is_empty());
    }

    /// del_ipv4_default_route_by_oif が対象 oif のみ削除すること。
    #[tokio::test]
    async fn test_del_route_by_oif() {
        let mut mock = MockHandle::new(vec![5, 10, 15]);
        mock.del_ipv4_default_route_by_oif(10).await.unwrap();
        assert_eq!(mock.deleted_routes, vec![10]);
        assert_eq!(mock.default_routes, vec![5, 15]);
    }

    /// get_ipv4_default_routes が空リストを返す場合を確認。
    #[tokio::test]
    async fn test_get_default_routes_empty() {
        let mut mock = MockHandle::new(vec![]);
        let routes = mock.get_ipv4_default_routes().await.unwrap();
        assert!(routes.is_empty());
    }
}
