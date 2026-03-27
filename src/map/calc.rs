use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;

use crate::error::MapEError;

use super::{
    port_set::calc_port_ranges,
    rule::{MapRule, MapeParams},
};

/// CE プレフィックスから EA-bits を抽出する。
///
/// RFC 7597 Section 5.2 に従い、CE プレフィックスのうちルール IPv6 プレフィックス (r ビット)
/// より後ろの ea_length ビットを返す。
///
/// # エラー
///
/// `ce_prefix.prefix_len() != rule.ipv6_prefix.prefix_len() + rule.ea_length`
/// の場合 `MapEError::InvalidCePrefix` を返す。
pub fn extract_ea_bits(ce_prefix: Ipv6Net, rule: &MapRule) -> Result<u64, MapEError> {
    let r = rule.ipv6_prefix.prefix_len() as u32;
    let ea_len = rule.ea_length as u32;

    if ce_prefix.prefix_len() as u32 != r + ea_len {
        return Err(MapEError::InvalidCePrefix);
    }

    if ea_len == 0 {
        return Ok(0);
    }

    let addr = u128::from(ce_prefix.network());
    // EA-bits はアドレスの左から r ビット目以降の ea_len ビット。
    // 右シフト量: 128 - r - ea_len
    let shift = 128 - r - ea_len;
    let mask = (1u128 << ea_len) - 1;
    let ea_bits = ((addr >> shift) & mask) as u64;

    Ok(ea_bits)
}

/// EA-bits から IPv4 アドレスと PSID を導出する。
///
/// EA-bits の上位 (ea_length - k) ビットが IPv4 サフィックス、下位 k ビットが PSID。
pub fn derive_ipv4_and_psid(ea_bits: u64, rule: &MapRule) -> (Ipv4Addr, u16) {
    let k = rule.port_params.psid_length as u32;

    // 下位 k ビット = PSID（k=0 の場合マスクは 0、PSID=0）
    let psid_mask = if k == 0 { 0u64 } else { (1u64 << k) - 1 };
    let psid = (ea_bits & psid_mask) as u16;

    // 上位ビット = IPv4 サフィックス
    let ipv4_suffix = (ea_bits >> k) as u32;

    // IPv4 プレフィックスのネットワークアドレスとサフィックスを OR で結合
    let ipv4_prefix_addr = u32::from(rule.ipv4_prefix.network());
    let ipv4 = Ipv4Addr::from(ipv4_prefix_addr | ipv4_suffix);

    (ipv4, psid)
}

/// CE IPv6 アドレスを構成する（RFC 7597 Section 5.2）。
///
/// ```text
/// [Rule IPv6 prefix (r bits)] | [EA-bits (ea_length bits)] | [0-pad (80-r-ea_len bits)]
/// | [IPv4 addr (32 bits, bits 80-111)] | [PSID << (16-k) (16 bits, bits 112-127)]
/// ```
///
/// CE プレフィックスに含まれる上位 (r + ea_length) ビットはそのまま保持し、
/// 残りのビット（80 ビット目以降）に IPv4 アドレスと PSID を配置する。
pub fn build_ce_ipv6(ce_prefix: Ipv6Net, rule: &MapRule, ea_bits: u64) -> Ipv6Addr {
    let (ipv4, psid) = derive_ipv4_and_psid(ea_bits, rule);
    let r_plus_ea = rule.ipv6_prefix.prefix_len() as u32 + rule.ea_length as u32;

    // CE プレフィックスのネットワークアドレスから開始し、上位 r+ea ビットのみを残す。
    let mut addr = u128::from(ce_prefix.network());
    let prefix_mask = if r_plus_ea == 0 {
        0u128
    } else {
        !0u128 << (128 - r_plus_ea)
    };
    addr &= prefix_mask;

    // ビット 80-111 に IPv4 アドレスを配置（左から 16 ビット分シフト）
    addr |= (u32::from(ipv4) as u128) << 16;

    // ビット 112-127 に PSID を配置（16 ビットフィールド内で左詰め）
    let k = rule.port_params.psid_length as u32;
    if k > 0 {
        addr |= (psid as u128) << (16 - k);
    }

    Ipv6Addr::from(addr)
}

/// CE プレフィックスと MAP ルールから MAP-E パラメータを計算する。
pub fn compute_mape_params(ce_prefix: Ipv6Net, rule: &MapRule) -> Result<MapeParams, MapEError> {
    let ea_bits = extract_ea_bits(ce_prefix, rule)?;
    let (ipv4, psid) = derive_ipv4_and_psid(ea_bits, rule);
    let ce_ipv6 = build_ce_ipv6(ce_prefix, rule, ea_bits);
    let port_ranges = calc_port_ranges(&rule.port_params, psid);

    Ok(MapeParams {
        ce_ipv6,
        ipv4,
        psid,
        port_ranges,
        br_address: rule.br_address,
        rule: rule.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use ipnet::{Ipv4Net, Ipv6Net};

    use super::*;
    use crate::map::rule::{MapRule, PortParams};

    /// テスト用 MapRule ヘルパー（v6plus 相当: a=4, k=8）
    fn make_rule(
        ipv6_prefix: &str,
        ipv4_prefix: &str,
        ea_length: u8,
        psid_offset: u8,
        psid_length: u8,
        br: &str,
    ) -> MapRule {
        MapRule {
            ipv6_prefix: Ipv6Net::from_str(ipv6_prefix).unwrap(),
            ipv4_prefix: Ipv4Net::from_str(ipv4_prefix).unwrap(),
            ea_length,
            is_fmr: true,
            br_address: Ipv6Addr::from_str(br).unwrap(),
            port_params: PortParams {
                psid_offset,
                psid_length,
            },
        }
    }

    // ----------------------------------------------------------------
    // extract_ea_bits
    // ----------------------------------------------------------------

    #[test]
    fn test_extract_ea_bits_ok() {
        // Rule IPv6: 2001:db8::/32, ea_length=16 → CE prefix は /48
        // CE prefix: 2001:db8:6401::/48
        //   bits 32..47 = 0x6401
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 0, 8, "2001:db8::1");
        let ce = Ipv6Net::from_str("2001:db8:6401::/48").unwrap();
        let ea = extract_ea_bits(ce, &rule).unwrap();
        assert_eq!(ea, 0x6401);
    }

    #[test]
    fn test_extract_ea_bits_mismatch_returns_error() {
        // ea_length=16 なので CE は /48 が正しいが /50 を渡す
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 0, 8, "2001:db8::1");
        let ce = Ipv6Net::from_str("2001:db8:6401::/50").unwrap();
        let result = extract_ea_bits(ce, &rule);
        assert!(matches!(result, Err(MapEError::InvalidCePrefix)));
    }

    #[test]
    fn test_extract_ea_bits_zero_ea_length() {
        let rule = make_rule("2001:db8::/32", "192.0.2.0/32", 0, 0, 0, "2001:db8::1");
        let ce = Ipv6Net::from_str("2001:db8::/32").unwrap();
        let ea = extract_ea_bits(ce, &rule).unwrap();
        assert_eq!(ea, 0);
    }

    // ----------------------------------------------------------------
    // derive_ipv4_and_psid
    // ----------------------------------------------------------------

    #[test]
    fn test_derive_ipv4_and_psid_basic() {
        // Rule IPv4: 192.0.2.0/24 (8-bit suffix), k=8, PSID=1
        // EA-bits = (100 << 8) | 1 = 0x6401
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 0, 8, "2001:db8::1");
        let (ipv4, psid) = derive_ipv4_and_psid(0x6401, &rule);
        assert_eq!(ipv4, "192.0.2.100".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(psid, 1);
    }

    #[test]
    fn test_derive_ipv4_and_psid_k0() {
        // k=0 の場合 PSID=0 が自明、EA-bits は全て IPv4 サフィックス
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 8, 0, 0, "2001:db8::1");
        let (ipv4, psid) = derive_ipv4_and_psid(0x64, &rule);
        assert_eq!(ipv4, "192.0.2.100".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(psid, 0);
    }

    // ----------------------------------------------------------------
    // build_ce_ipv6
    // ----------------------------------------------------------------

    #[test]
    fn test_build_ce_ipv6_rfc7597() {
        // Rule IPv6: 2001:db8::/32, IPv4: 192.0.2.0/24 (8-bit suffix), k=8, PSID=1
        // CE prefix: 2001:db8:6401::/48
        // Expected CE IPv6: 2001:db8:6401::c000:264:100
        //   bits 80-111: 192.0.2.100 = 0xc0000264
        //   bits 112-127: 1 << (16-8) = 0x0100
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 0, 8, "2001:db8::1");
        let ce_prefix = Ipv6Net::from_str("2001:db8:6401::/48").unwrap();
        let ea_bits = extract_ea_bits(ce_prefix, &rule).unwrap();
        let ce_ipv6 = build_ce_ipv6(ce_prefix, &rule, ea_bits);

        let expected = Ipv6Addr::from_str("2001:db8:6401::c000:264:100").unwrap();
        assert_eq!(ce_ipv6, expected);
    }

    #[test]
    fn test_build_ce_ipv6_psid0() {
        // PSID=0 の場合、下位 16 ビットのフィールドも 0
        // Rule IPv6: 2001:db8::/32, IPv4: 192.0.2.0/24 (8-bit suffix), k=8, PSID=0
        // EA-bits = (5 << 8) | 0 = 0x0500
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 0, 8, "2001:db8::1");
        let ce_prefix = Ipv6Net::from_str("2001:db8:0500::/48").unwrap();
        let ea_bits = extract_ea_bits(ce_prefix, &rule).unwrap();
        let ce_ipv6 = build_ce_ipv6(ce_prefix, &rule, ea_bits);

        // IPv4 = 192.0.2.5, PSID = 0
        // bits 80-111: 0xc0000205
        // bits 112-127: 0x0000
        let expected = Ipv6Addr::from_str("2001:db8:500::c000:205:0").unwrap();
        assert_eq!(ce_ipv6, expected);
    }

    // ----------------------------------------------------------------
    // compute_mape_params
    // ----------------------------------------------------------------

    #[test]
    fn test_compute_mape_params_v6plus() {
        // v6plus 相当: a=4, k=8, PSID=5
        // Rule IPv6: 2001:db8::/32, IPv4: 192.0.2.0/24, ea_length=16
        // CE prefix: 2001:db8:6405::/48
        //   EA-bits = 0x6405 → IPv4 suffix=0x64=100, PSID=5
        let rule = make_rule("2001:db8::/32", "192.0.2.0/24", 16, 4, 8, "2001:db8::1");
        let ce_prefix = Ipv6Net::from_str("2001:db8:6405::/48").unwrap();
        let params = compute_mape_params(ce_prefix, &rule).unwrap();

        assert_eq!(
            params.ipv4,
            "192.0.2.100".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(params.psid, 5);

        // ポート総数: R=1..15, j=0..15 → 15 * 16 = 240
        let total: usize = params
            .port_ranges
            .iter()
            .map(|r| (*r.end() - *r.start()) as usize + 1)
            .sum();
        assert_eq!(total, 240);
    }
}
