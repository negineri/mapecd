use std::net::{Ipv6Addr, SocketAddrV6};

use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, info};

use super::option_mape::MapeContainerOption;
use super::packet::build_solicit;
use super::Dhcpv6Error;

/// DHCPv6 クライアントポート
const CLIENT_PORT: u16 = 546;
/// DHCPv6 サーバー/リレーポート
const SERVER_PORT: u16 = 547;
/// All_DHCP_Relay_Agents_and_Servers マルチキャストアドレス
const ALL_DHCP_RELAY_AND_SERVERS: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x0001, 0x0002);

/// DHCPv6 クライアント
pub struct Dhcpv6Client {
    interface: String,
    socket: Socket,
}

impl Dhcpv6Client {
    pub fn new(interface: &str) -> Result<Self, Dhcpv6Error> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_only_v6(true)?;

        let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, CLIENT_PORT, 0, 0);
        socket.bind(&bind_addr.into())?;

        info!("DHCPv6 ソケットをバインドしました ({}:{})", Ipv6Addr::UNSPECIFIED, CLIENT_PORT);

        Ok(Self {
            interface: interface.to_string(),
            socket,
        })
    }

    /// MAP-E オプションを取得するまで DHCPv6 ネゴシエーションを実行
    pub async fn acquire_mape_config(
        &self,
    ) -> Result<MapeContainerOption, Dhcpv6Error> {
        info!("DHCPv6 ネゴシエーションを開始します (interface: {})", self.interface);

        let solicit = build_solicit();
        debug!("Solicit を送信します");

        // TODO: Solicit 送信 → Advertise 受信 → Request 送信 → Reply 受信
        // ステートマシンの完全実装

        Err(Dhcpv6Error::MapeOptionNotFound)
    }
}
