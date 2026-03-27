use std::{
    net::{Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// OPTION_S46_PORTPARAMS から取得したポートパラメータ。
///
/// 省略時のデフォルト: psid_offset=0 (a=0), psid_length=0 (k=0)。
/// k=0 の場合 PSID は 0 ビット幅であり PSID=0 が自明。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortParams {
    /// a: psid_offset (除外ビット数)。デフォルト 0。
    pub psid_offset: u8,
    /// k: psid_length (PSID ビット幅)。デフォルト 0。
    pub psid_length: u8,
}

impl Default for PortParams {
    fn default() -> Self {
        Self {
            psid_offset: 0,
            psid_length: 0,
        }
    }
}

/// OPTION_S46_RULE から取得した MAP-E ルール。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRule {
    /// ルール IPv6 プレフィックス (r ビット)
    pub ipv6_prefix: Ipv6Net,
    /// ルール IPv4 プレフィックス
    pub ipv4_prefix: Ipv4Net,
    /// EA-bits 長
    pub ea_length: u8,
    /// FMR (Forwarding Mapping Rule) フラグ (RFC 7597)
    pub is_fmr: bool,
    /// BR IPv6 アドレス (OPTION_S46_BR)
    pub br_address: Ipv6Addr,
    /// ポートパラメータ (OPTION_S46_PORTPARAMS)
    pub port_params: PortParams,
}

/// MAP-E 計算結果。CE IPv6 アドレス・IPv4 アドレス・PSID・ポート範囲を保持する。
#[derive(Debug, Clone)]
pub struct MapeParams {
    /// CE IPv6 アドレス (RFC 7597 Section 5.2 に従い導出)
    pub ce_ipv6: Ipv6Addr,
    /// 導出された IPv4 アドレス
    pub ipv4: Ipv4Addr,
    /// PSID 値
    pub psid: u16,
    /// この CE に割り当てられたポート範囲
    pub port_ranges: Vec<RangeInclusive<u16>>,
    /// BR IPv6 アドレス
    pub br_address: Ipv6Addr,
    /// 使用した MAP ルール
    pub rule: MapRule,
}
