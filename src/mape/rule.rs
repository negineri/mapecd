use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::dhcpv6::option_mape::S46Rule;

use super::MapeError;

/// MAP-E マッピングルール（RFC 7597）
#[derive(Debug, Clone)]
pub struct MapeRule {
    /// Basic Mapping Rule (BMR)
    pub bmr: S46Rule,
    /// CE の IPv6 アドレス（DHCPv6 で割り当てられたプレフィックスから算出）
    pub ce_ipv6_prefix: Ipv6Net,
}

impl MapeRule {
    pub fn new(bmr: S46Rule, ce_ipv6_prefix: Ipv6Net) -> Self {
        Self { bmr, ce_ipv6_prefix }
    }

    /// CE の MAP IPv6 アドレスを計算する
    ///
    /// MAP IPv6 アドレス = Rule IPv6 Prefix + EA-bits + IID
    pub fn map_ipv6_address(&self) -> Result<Ipv6Addr, MapeError> {
        let ea_bits = self.extract_ea_bits()?;
        // TODO: EA-bits を IPv6 プレフィックスに埋め込む
        Ok(self.ce_ipv6_prefix.network())
    }

    /// EA-bits を抽出する
    ///
    /// EA-bits = IPv4 サフィックス + PSID
    pub fn extract_ea_bits(&self) -> Result<u64, MapeError> {
        let ea_len = self.bmr.ea_len as u32;
        let ipv4_suffix_len = 32 - self.bmr.ipv4_prefix_len as u32;

        // PSID 長 = EA-bits 長 - IPv4 サフィックス長
        let psid_len = ea_len.saturating_sub(ipv4_suffix_len) as u8;

        let ipv4_octets = self.bmr.ipv4_prefix.octets();
        let ipv4_u32 = u32::from_be_bytes(ipv4_octets);
        let ipv4_suffix_mask = (1u32 << ipv4_suffix_len) - 1;
        let ipv4_suffix = ipv4_u32 & ipv4_suffix_mask;

        let psid = self.bmr.psid.unwrap_or(0) as u64;
        let ea_bits = ((ipv4_suffix as u64) << psid_len) | psid;

        Ok(ea_bits)
    }

    /// CE に割り当てられた IPv4 アドレスを返す
    pub fn ipv4_address(&self) -> Ipv4Addr {
        self.bmr.ipv4_prefix
    }

    /// PSID オフセットを返す（デフォルト 6）
    pub fn psid_offset(&self) -> u8 {
        self.bmr.psid_offset.unwrap_or(6)
    }

    /// PSID 長を返す
    pub fn psid_len(&self) -> u8 {
        self.bmr.psid_len.unwrap_or(0)
    }

    /// PSID 値を返す
    pub fn psid(&self) -> u16 {
        self.bmr.psid.unwrap_or(0)
    }
}
