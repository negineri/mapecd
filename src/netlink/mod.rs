#[cfg(target_os = "linux")]
pub mod interface;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
pub mod tunnel;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetlinkError {
    #[error("Netlink 接続エラー: {0}")]
    Connection(String),

    #[error("インターフェース '{0}' が見つかりません")]
    InterfaceNotFound(String),

    #[error("アドレス設定エラー: {0}")]
    AddressConfig(String),

    #[error("ルーティング設定エラー: {0}")]
    RouteConfig(String),

    #[error("トンネル設定エラー: {0}")]
    TunnelConfig(String),

    #[error("IO エラー: {0}")]
    Io(#[from] std::io::Error),
}
