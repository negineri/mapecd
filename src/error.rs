use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MapEError {
    #[error("config file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// EA-bits 長と CE prefix 長の不一致
    #[error("invalid CE prefix: EA-bits length and CE prefix length mismatch")]
    InvalidCePrefix,

    /// IA_PD にマッチする MAP Rule が pending_map_rules に存在しない場合
    #[error("no prefix match: IA_PD prefix does not match any MAP rule")]
    NoPrefixMatch,

    /// OPTION_S46_BR が省略された場合
    #[error("missing BR address: OPTION_S46_BR is required but not present")]
    MissingBrAddress,

    /// calc_port_ranges の結果が空の場合の nftables 適用ガード
    #[error("empty port ranges: cannot apply nftables ruleset with no port ranges")]
    EmptyPortRanges,

    #[error("netlink error: {0}")]
    NetlinkError(String),

    #[error("nft error: {0}")]
    NftError(String),
}
