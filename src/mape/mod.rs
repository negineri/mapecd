pub mod address;
pub mod rule;

pub use rule::MapeRule;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MapeError {
    #[error("IPv6 プレフィックスが不正です: {0}")]
    InvalidIpv6Prefix(String),

    #[error("IPv4 プレフィックスが不正です: {0}")]
    InvalidIpv4Prefix(String),

    #[error("EA-bits 計算エラー: {0}")]
    EaBitsCalcError(String),

    #[error("PSID が有効範囲外です: psid={psid}, psid_len={psid_len}")]
    InvalidPsid { psid: u16, psid_len: u8 },
}
