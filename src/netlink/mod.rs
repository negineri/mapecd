//! Netlink 操作モジュール（Linux 専用）
//!
//! CE IPv6/IPv4 アドレス付与、ip6tnl トンネル作成、IPv4 デフォルトルート設定を
//! Netlink 経由で実行する。
//!
//! テスト時は `NetlinkHandle` トレイトを mock 実装することで
//! カーネル操作なしに単体テストが可能。

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::MapEError;

pub mod addr;
pub mod route;
pub mod tunnel;

/// Netlink 操作を抽象化するトレイト。
///
/// 本番実装は `RtNetlinkHandle`、テスト用の mock 実装は各テストモジュールで定義する。
pub trait NetlinkHandle: Send {
    /// upstream_interface に CE IPv6 アドレス（/128）を付与する。
    fn add_ipv6_addr(
        &mut self,
        ifindex: u32,
        addr: Ipv6Addr,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// upstream_interface から CE IPv6 アドレス（/128）を削除する。
    fn del_ipv6_addr(
        &mut self,
        ifindex: u32,
        addr: Ipv6Addr,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// トンネルインターフェースに CE IPv4 アドレス（/32）を付与する。
    fn add_ipv4_addr(
        &mut self,
        ifindex: u32,
        addr: Ipv4Addr,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// トンネルインターフェースから CE IPv4 アドレス（/32）を削除する。
    fn del_ipv4_addr(
        &mut self,
        ifindex: u32,
        addr: Ipv4Addr,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// インターフェース名から現在の MTU を取得する。
    fn get_link_mtu(
        &mut self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<u32, MapEError>> + Send;

    /// インターフェース名から ifindex を取得する。
    fn get_link_index(
        &mut self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<u32, MapEError>> + Send;

    /// ip6tnl トンネルを作成し、作成後の ifindex を返す。
    ///
    /// mode は ipip6 固定（PROTO=IPPROTO_IPIP=4）、encaplimit=0。
    fn create_ip6tnl(
        &mut self,
        name: &str,
        local: Ipv6Addr,
        remote: Ipv6Addr,
        link_index: u32,
        mtu: u32,
    ) -> impl std::future::Future<Output = Result<u32, MapEError>> + Send;

    /// 指定 ifindex のリンク（トンネル）を削除する。
    fn delete_link(
        &mut self,
        ifindex: u32,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// 現在の IPv4 デフォルトルート（0.0.0.0/0）の oif ifindex 一覧を返す。
    fn get_ipv4_default_routes(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Vec<u32>, MapEError>> + Send;

    /// 指定 oif 経由の IPv4 デフォルトルートを追加する。
    fn add_ipv4_default_route(
        &mut self,
        oif: u32,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;

    /// 指定 oif 経由の IPv4 デフォルトルートを削除する。
    fn del_ipv4_default_route_by_oif(
        &mut self,
        oif: u32,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;
}

/// `rtnetlink::Handle` を使用した本番用 `NetlinkHandle` 実装。
pub struct RtNetlinkHandle {
    pub(crate) handle: rtnetlink::Handle,
}

impl RtNetlinkHandle {
    /// `rtnetlink::new_connection()` で取得した Handle を渡して構築する。
    pub fn new(handle: rtnetlink::Handle) -> Self {
        Self { handle }
    }
}

impl NetlinkHandle for RtNetlinkHandle {
    async fn add_ipv6_addr(&mut self, ifindex: u32, addr: Ipv6Addr) -> Result<(), MapEError> {
        addr::add_ipv6_addr(&self.handle, ifindex, addr).await
    }

    async fn del_ipv6_addr(&mut self, ifindex: u32, addr: Ipv6Addr) -> Result<(), MapEError> {
        addr::del_ipv6_addr(&self.handle, ifindex, addr).await
    }

    async fn add_ipv4_addr(&mut self, ifindex: u32, addr: Ipv4Addr) -> Result<(), MapEError> {
        addr::add_ipv4_addr(&self.handle, ifindex, addr).await
    }

    async fn del_ipv4_addr(&mut self, ifindex: u32, addr: Ipv4Addr) -> Result<(), MapEError> {
        addr::del_ipv4_addr(&self.handle, ifindex, addr).await
    }

    async fn get_link_mtu(&mut self, name: &str) -> Result<u32, MapEError> {
        tunnel::get_link_mtu(&mut self.handle, name).await
    }

    async fn get_link_index(&mut self, name: &str) -> Result<u32, MapEError> {
        tunnel::get_link_index(&mut self.handle, name).await
    }

    async fn create_ip6tnl(
        &mut self,
        name: &str,
        local: Ipv6Addr,
        remote: Ipv6Addr,
        link_index: u32,
        mtu: u32,
    ) -> Result<u32, MapEError> {
        tunnel::create_ip6tnl(&mut self.handle, name, local, remote, link_index, mtu).await
    }

    async fn delete_link(&mut self, ifindex: u32) -> Result<(), MapEError> {
        tunnel::delete_link(&mut self.handle, ifindex).await
    }

    async fn get_ipv4_default_routes(&mut self) -> Result<Vec<u32>, MapEError> {
        route::get_ipv4_default_routes(&mut self.handle).await
    }

    async fn add_ipv4_default_route(&mut self, oif: u32) -> Result<(), MapEError> {
        route::add_ipv4_default_route(&mut self.handle, oif).await
    }

    async fn del_ipv4_default_route_by_oif(&mut self, oif: u32) -> Result<(), MapEError> {
        route::del_ipv4_default_route_by_oif(&mut self.handle, oif).await
    }
}
