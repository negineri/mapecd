/// RFC 7598 - DHCPv6 Options for Configuration of Softwire Address and Port-Mapped Clients
///
/// OPTION_S46_CONT_MAPE (95) のカスタムパーサー
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use super::Dhcpv6Error;

/// OPTION_S46_CONT_MAPE オプションコード
pub const OPTION_S46_CONT_MAPE: u16 = 95;
/// OPTION_S46_RULE オプションコード
pub const OPTION_S46_RULE: u16 = 89;
/// OPTION_S46_BR オプションコード (Border Relay アドレス)
pub const OPTION_S46_BR: u16 = 90;

/// MAP-E コンテナオプション（OPTION_S46_CONT_MAPE）
#[derive(Debug, Clone)]
pub struct MapeContainerOption {
    pub rules: Vec<S46Rule>,
    pub br_addresses: Vec<Ipv6Addr>,
}

/// S46 マッピングルール（OPTION_S46_RULE）
#[derive(Debug, Clone)]
pub struct S46Rule {
    /// FMR フラグ（Forwarding Mapping Rule として使用可能か）
    pub is_fmr: bool,
    /// EA-bits 長
    pub ea_len: u8,
    /// IPv4 プレフィックス長
    pub ipv4_prefix_len: u8,
    /// IPv4 プレフィックス
    pub ipv4_prefix: Ipv4Addr,
    /// IPv6 プレフィックス
    pub ipv6_prefix: Ipv6Net,
    /// PSID オフセット（オプション）
    pub psid_offset: Option<u8>,
    /// PSID 長（オプション）
    pub psid_len: Option<u8>,
    /// PSID 値（オプション）
    pub psid: Option<u16>,
}

impl MapeContainerOption {
    /// OPTION_S46_CONT_MAPE のオプションデータをパースする
    ///
    /// # Arguments
    /// * `data` - オプションコードと長さを除いたペイロード
    pub fn parse(data: &[u8]) -> Result<Self, Dhcpv6Error> {
        let mut rules = Vec::new();
        let mut br_addresses = Vec::new();
        let mut cursor = data;

        while cursor.len() >= 4 {
            let opt_code = u16::from_be_bytes([cursor[0], cursor[1]]);
            let opt_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
            cursor = &cursor[4..];

            if cursor.len() < opt_len {
                return Err(Dhcpv6Error::Parse(format!(
                    "オプションデータが不足しています: code={opt_code}, len={opt_len}, remaining={}",
                    cursor.len()
                )));
            }

            let opt_data = &cursor[..opt_len];
            cursor = &cursor[opt_len..];

            match opt_code {
                OPTION_S46_RULE => {
                    rules.push(S46Rule::parse(opt_data)?);
                }
                OPTION_S46_BR => {
                    if opt_len % 16 != 0 {
                        return Err(Dhcpv6Error::Parse(format!(
                            "OPTION_S46_BR の長さが不正です: {opt_len}"
                        )));
                    }
                    for chunk in opt_data.chunks(16) {
                        let octets: [u8; 16] = chunk.try_into().unwrap();
                        br_addresses.push(Ipv6Addr::from(octets));
                    }
                }
                _ => {
                    tracing::debug!("未知のサブオプション: code={opt_code}, len={opt_len}");
                }
            }
        }

        Ok(Self { rules, br_addresses })
    }
}

impl S46Rule {
    fn parse(data: &[u8]) -> Result<Self, Dhcpv6Error> {
        // 最小サイズ: flags(1) + ea-len(1) + prefix4-len(1) + ipv4-prefix(4) + prefix6-len(1) + ipv6-prefix(可変)
        if data.len() < 8 {
            return Err(Dhcpv6Error::Parse(format!(
                "OPTION_S46_RULE のデータが短すぎます: {}",
                data.len()
            )));
        }

        let flags = data[0];
        let is_fmr = (flags & 0x01) != 0;
        let ea_len = data[1];
        let ipv4_prefix_len = data[2];

        let ipv4_prefix = Ipv4Addr::new(data[3], data[4], data[5], data[6]);
        let ipv6_prefix_len = data[7];

        // IPv6 プレフィックスのバイト長（切り上げ）
        let ipv6_prefix_bytes = (ipv6_prefix_len as usize + 7) / 8;
        if data.len() < 8 + ipv6_prefix_bytes {
            return Err(Dhcpv6Error::Parse(
                "OPTION_S46_RULE の IPv6 プレフィックスデータが不足しています".into(),
            ));
        }

        let mut ipv6_octets = [0u8; 16];
        ipv6_octets[..ipv6_prefix_bytes].copy_from_slice(&data[8..8 + ipv6_prefix_bytes]);
        let ipv6_addr = Ipv6Addr::from(ipv6_octets);
        let ipv6_prefix = Ipv6Net::new(ipv6_addr, ipv6_prefix_len)
            .map_err(|e| Dhcpv6Error::Parse(format!("IPv6 プレフィックスが不正: {e}")))?;

        // OPTION_S46_PORTPARAMS サブオプションのパース（オプション）
        let remaining = &data[8 + ipv6_prefix_bytes..];
        let (psid_offset, psid_len, psid) = parse_portparams(remaining)?;

        Ok(Self {
            is_fmr,
            ea_len,
            ipv4_prefix_len,
            ipv4_prefix,
            ipv6_prefix,
            psid_offset,
            psid_len,
            psid,
        })
    }
}

/// OPTION_S46_PORTPARAMS (93) をパースする
fn parse_portparams(
    data: &[u8],
) -> Result<(Option<u8>, Option<u8>, Option<u16>), Dhcpv6Error> {
    const OPTION_S46_PORTPARAMS: u16 = 93;

    let mut cursor = data;
    while cursor.len() >= 4 {
        let opt_code = u16::from_be_bytes([cursor[0], cursor[1]]);
        let opt_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];

        if cursor.len() < opt_len {
            break;
        }
        let opt_data = &cursor[..opt_len];
        cursor = &cursor[opt_len..];

        if opt_code == OPTION_S46_PORTPARAMS && opt_len >= 4 {
            let offset = opt_data[0];
            let psid_len = opt_data[1];
            let psid = u16::from_be_bytes([opt_data[2], opt_data[3]]);
            return Ok((Some(offset), Some(psid_len), Some(psid)));
        }
    }

    Ok((None, None, None))
}
