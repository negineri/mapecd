use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("DHCPv6 エラー: {0}")]
    Dhcpv6(#[from] crate::dhcpv6::Dhcpv6Error),

    #[error("MAP-E ルール計算エラー: {0}")]
    Mape(#[from] crate::mape::MapeError),

    #[error("Netlink エラー: {0}")]
    Netlink(#[from] crate::netlink::NetlinkError),

    #[error("設定エラー: {0}")]
    Config(#[from] config::ConfigError),

    #[error("IO エラー: {0}")]
    Io(#[from] std::io::Error),
}
