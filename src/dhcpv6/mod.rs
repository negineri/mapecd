pub mod client;
pub mod option_mape;
pub mod packet;


use thiserror::Error;

#[derive(Debug, Error)]
pub enum Dhcpv6Error {
    #[error("ソケット作成エラー: {0}")]
    Socket(#[from] std::io::Error),

    #[error("パケットパースエラー: {0}")]
    Parse(String),

    #[error("タイムアウト")]
    Timeout,

    #[error("MAP-E オプションが見つかりません")]
    MapeOptionNotFound,
}
