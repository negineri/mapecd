//! DHCPv6 パーサー
//!
//! RFC 7598 の OPTION_S46_CONT_MAPE (94)・OPTION_S46_RULE (89)・
//! OPTION_S46_BR (90)・OPTION_S46_PORTPARAMS (93) を手書きバイトパーサーで解析する。
//! IA_PD (OPTION_IA_PD=25) / IAPREFIX (OPTION_IAPREFIX=26) は dhcproto に委譲する。

use std::net::{Ipv4Addr, Ipv6Addr};

use dhcproto::{
    v6::{DhcpOption, IAPrefix, OptionCode, Status, IAPD, Message},
    Decodable, Decoder,
};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::{
    error::MapEError,
    map::rule::{MapRule, PortParams},
};

/// RFC 7598 S46 オプションコード定数
const OPT_S46_RULE: u16 = 89;
const OPT_S46_BR: u16 = 90;
const OPT_S46_PORTPARAMS: u16 = 93;
#[cfg(test)]
const OPT_S46_CONT_MAPE: u16 = 94;

// ────────────────────────────────────────────────────────────────────
// 公開 API
// ────────────────────────────────────────────────────────────────────

/// IA_PD 情報（CE プレフィックス + ライフタイム）。
///
/// `parse_ia_pd_info` の戻り値として使用し、Phase 4 の再要求タイマーで T1/T2 を利用する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPdInfo {
    /// CE プレフィックス (IAPREFIX の prefix_ip / prefix_len)
    pub prefix: Ipv6Net,
    /// T1: サーバーへの再要求まで (秒)
    pub t1: u32,
    /// T2: Any Server への Rebind まで (秒)
    pub t2: u32,
    /// valid-lifetime (秒)
    pub valid_lifetime: u32,
}

/// 生の DHCPv6 Reply バイト列から OPTION_S46_CONT_MAPE (94) を探し、
/// 内包するすべての MAP ルールを返す。
///
/// - Option 94 が存在しない場合: `Ok(None)` を返す。
/// - Option 94 が複数存在する場合: **最初に現れたもの**だけを処理する。
/// - BR アドレス (OPTION_S46_BR) が見つからない場合: `Err(MissingBrAddress)`。
///
/// # 引数
///
/// `data` は DHCPv6 メッセージのバイト列（msg-type から始まり UDP/IP ヘッダーを含まない）。
pub fn parse_mape_container(data: &[u8]) -> Result<Option<Vec<MapRule>>, MapEError> {
    let msg = match Message::decode(&mut Decoder::new(data)) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };

    let container_payload = msg
        .opts()
        .iter()
        .find_map(|opt| match opt {
            DhcpOption::Unknown(unk) if unk.code() == OptionCode::S46ContMape => {
                Some(unk.data().to_vec())
            }
            _ => None,
        });

    match container_payload {
        None => Ok(None),
        Some(payload) => parse_s46_cont_mape(&payload).map(Some),
    }
}

/// 生の DHCPv6 Reply バイト列から IA_PD の CE プレフィックスを取得する。
///
/// `iaid` が `Some(id)` の場合は一致する IA_PD のみを処理し、`None` の場合は最初の IA_PD を使用する。
/// IA_PD が存在しない・ステータスが Success でない場合は `None` を返す。
pub fn parse_ia_pd(data: &[u8], iaid: Option<u32>) -> Option<Ipv6Net> {
    parse_ia_pd_info(data, iaid).map(|info| info.prefix)
}

/// 生の DHCPv6 Reply バイト列から IA_PD の CE プレフィックスおよびライフタイム情報を取得する。
///
/// T1=0 / T2=0 の場合は RFC 3315 Section 22.4 に従い補完する:
/// - `T1 = valid_lifetime / 2`
/// - `T2 = valid_lifetime * 4 / 5` (= 80%)
/// - `valid_lifetime = 0xFFFFFFFF`（無限大）の場合は T1/T2 も `u32::MAX` に補完する。
pub fn parse_ia_pd_info(data: &[u8], iaid: Option<u32>) -> Option<IaPdInfo> {
    let msg = Message::decode(&mut Decoder::new(data)).ok()?;

    let iapd = find_iapd(msg.opts().iter(), iaid)?;

    // IAPREFIX sub-option を探す
    let iaprefix = iapd.opts.iter().find_map(|opt| {
        if let DhcpOption::IAPrefix(p) = opt {
            Some(p)
        } else {
            None
        }
    })?;

    // IAPREFIX 内の StatusCode が NoAddrsAvail 等でないことを確認
    // (Success または StatusCode なし の場合のみ採用)
    for opt in iapd.opts.iter() {
        if let DhcpOption::StatusCode(sc) = opt {
            if sc.status != Status::Success {
                return None;
            }
        }
    }

    let prefix = build_ia_prefix(iaprefix)?;
    let valid_lifetime = iaprefix.valid_lifetime;

    let t1 = complement_timer(iapd.t1, valid_lifetime, 2);
    let t2 = complement_timer(iapd.t2, valid_lifetime, 5);

    Some(IaPdInfo {
        prefix,
        t1,
        t2,
        valid_lifetime,
    })
}

// ────────────────────────────────────────────────────────────────────
// 内部実装: S46 コンテナ・ルールのパース
// ────────────────────────────────────────────────────────────────────

/// OPTION_S46_CONT_MAPE のペイロード（sub-options の TLV 列）をパースする。
fn parse_s46_cont_mape(payload: &[u8]) -> Result<Vec<MapRule>, MapEError> {
    // まず BR アドレスを収集する
    let mut br_addr: Option<Ipv6Addr> = None;
    let mut rule_payloads: Vec<Vec<u8>> = Vec::new();

    iter_opts(payload, |code, data| {
        match code {
            OPT_S46_BR => {
                if br_addr.is_none() {
                    if let Some(addr) = parse_s46_br(data) {
                        br_addr = Some(addr);
                    }
                }
            }
            OPT_S46_RULE => {
                rule_payloads.push(data.to_vec());
            }
            _ => {}
        }
    });

    let br = br_addr.ok_or(MapEError::MissingBrAddress)?;

    let mut rules = Vec::with_capacity(rule_payloads.len());
    for rp in rule_payloads {
        match parse_s46_rule(&rp, br) {
            Ok(rule) => rules.push(rule),
            Err(e) => return Err(e),
        }
    }
    Ok(rules)
}

/// OPTION_S46_BR のペイロード（16 バイトの IPv6 アドレス）をパースする。
fn parse_s46_br(data: &[u8]) -> Option<Ipv6Addr> {
    if data.len() < 16 {
        return None;
    }
    let bytes: [u8; 16] = data[..16].try_into().ok()?;
    Some(Ipv6Addr::from(bytes))
}

/// OPTION_S46_RULE のペイロードをパースして `MapRule` を返す。
///
/// ペイロード構造 (RFC 7598 Section 4.1):
/// ```text
/// flags (1) | ea-len (1) | prefix4-len (1) | IPv4 prefix (ceil(prefix4-len/8) bytes)
/// | prefix6-len (1) | IPv6 prefix (ceil(prefix6-len/8) bytes) | sub-options
/// ```
fn parse_s46_rule(payload: &[u8], br_addr: Ipv6Addr) -> Result<MapRule, MapEError> {
    if payload.len() < 3 {
        return Err(MapEError::InvalidConfig(
            "S46_RULE payload too short".to_string(),
        ));
    }

    let mut pos = 0;

    let flags = payload[pos];
    pos += 1;
    let is_fme = (flags & 0x01) != 0;

    let ea_length = payload[pos];
    pos += 1;

    let prefix4_len = payload[pos];
    pos += 1;
    if prefix4_len > 32 {
        return Err(MapEError::InvalidConfig(format!(
            "S46_RULE prefix4-len {prefix4_len} > 32"
        )));
    }

    let ipv4_bytes_len = ((prefix4_len as usize) + 7) / 8;
    if pos + ipv4_bytes_len > payload.len() {
        return Err(MapEError::InvalidConfig(
            "S46_RULE payload truncated at IPv4 prefix".to_string(),
        ));
    }
    let mut ipv4_raw = [0u8; 4];
    ipv4_raw[..ipv4_bytes_len].copy_from_slice(&payload[pos..pos + ipv4_bytes_len]);
    pos += ipv4_bytes_len;

    let ipv4_addr = Ipv4Addr::from(ipv4_raw);
    let ipv4_prefix = Ipv4Net::new(ipv4_addr, prefix4_len)
        .map_err(|e| MapEError::InvalidConfig(format!("S46_RULE invalid IPv4 prefix: {e}")))?;
    let ipv4_prefix = ipv4_prefix.trunc(); // ホストビット正規化

    if pos >= payload.len() {
        return Err(MapEError::InvalidConfig(
            "S46_RULE payload truncated at prefix6-len".to_string(),
        ));
    }
    let prefix6_len = payload[pos];
    pos += 1;
    if prefix6_len > 128 {
        return Err(MapEError::InvalidConfig(format!(
            "S46_RULE prefix6-len {prefix6_len} > 128"
        )));
    }

    let ipv6_bytes_len = ((prefix6_len as usize) + 7) / 8;
    if pos + ipv6_bytes_len > payload.len() {
        return Err(MapEError::InvalidConfig(
            "S46_RULE payload truncated at IPv6 prefix".to_string(),
        ));
    }
    let mut ipv6_raw = [0u8; 16];
    ipv6_raw[..ipv6_bytes_len].copy_from_slice(&payload[pos..pos + ipv6_bytes_len]);
    pos += ipv6_bytes_len;

    let ipv6_addr = Ipv6Addr::from(ipv6_raw);
    let ipv6_prefix = Ipv6Net::new(ipv6_addr, prefix6_len)
        .map_err(|e| MapEError::InvalidConfig(format!("S46_RULE invalid IPv6 prefix: {e}")))?;
    let ipv6_prefix = ipv6_prefix.trunc(); // ホストビット正規化

    // 残りは sub-options: OPTION_S46_PORTPARAMS (93) を探す
    let mut port_params = PortParams::default();
    iter_opts(&payload[pos..], |code, data| {
        if code == OPT_S46_PORTPARAMS && data.len() >= 4 {
            port_params = PortParams {
                psid_offset: data[0],
                psid_length: data[1],
                // data[2..3] は PSID（EA-bits から導出するため格納しない）
            };
        }
    });

    Ok(MapRule {
        ipv6_prefix,
        ipv4_prefix,
        ea_length,
        is_fme,
        br_address: br_addr,
        port_params,
    })
}

/// TLV 形式 (2-byte code, 2-byte length, data) のオプション列をスキャンし、
/// 各エントリに対してクロージャ `f` を呼び出す。
fn iter_opts<F: FnMut(u16, &[u8])>(payload: &[u8], mut f: F) {
    let mut pos = 0;
    while pos + 4 <= payload.len() {
        let code = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;
        if pos + len > payload.len() {
            break;
        }
        f(code, &payload[pos..pos + len]);
        pos += len;
    }
}

// ────────────────────────────────────────────────────────────────────
// 内部実装: IA_PD / IAPREFIX のパース
// ────────────────────────────────────────────────────────────────────

/// dhcproto の Option イテレーターから、対象 IAID の IA_PD を探す。
fn find_iapd<'a>(
    opts: impl Iterator<Item = &'a DhcpOption>,
    iaid: Option<u32>,
) -> Option<&'a IAPD> {
    for opt in opts {
        if let DhcpOption::IAPD(iapd) = opt {
            match iaid {
                Some(id) if iapd.id != id => continue,
                _ => return Some(iapd),
            }
        }
    }
    None
}

/// IAPREFIX から `Ipv6Net` を構築する。
fn build_ia_prefix(iaprefix: &IAPrefix) -> Option<Ipv6Net> {
    Ipv6Net::new(iaprefix.prefix_ip, iaprefix.prefix_len)
        .ok()
        .map(|n| n.trunc())
}

/// ライフタイムゼロ補完。
///
/// `divisor` は分母: T1 の場合 `2`、T2 の場合 `5`（`valid * 4 / 5` に相当）。
fn complement_timer(timer: u32, valid_lifetime: u32, divisor: u32) -> u32 {
    if timer != 0 {
        return timer;
    }
    if valid_lifetime == u32::MAX {
        return u32::MAX;
    }
    if divisor == 2 {
        valid_lifetime / 2
    } else {
        // divisor == 5 → 80%
        ((valid_lifetime as u64) * 4 / 5) as u32
    }
}

// ────────────────────────────────────────────────────────────────────
// テスト
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ipnet::Ipv6Net;

    use super::*;
    use crate::map::rule::PortParams;

    // ────────────────────────────────────────────────────────────────
    // テストベクター構築ヘルパー
    // ────────────────────────────────────────────────────────────────

    /// オプション TLV を構築する。
    fn opt(code: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// DHCPv6 Reply メッセージを構築する (msg-type=7, xid=0x123456, opts=options)。
    fn reply_msg(options: &[u8]) -> Vec<u8> {
        let mut v = vec![0x07, 0x12, 0x34, 0x56]; // Reply + xid
        v.extend_from_slice(options);
        v
    }

    /// OPTION_S46_BR ペイロード (BR アドレスの 16 バイト)。
    fn s46_br_payload(addr: Ipv6Addr) -> Vec<u8> {
        addr.octets().to_vec()
    }

    /// OPTION_S46_PORTPARAMS ペイロード (4 バイト: offset, psid-len, psid[2])。
    fn s46_portparams_payload(offset: u8, psid_len: u8, psid: u16) -> Vec<u8> {
        let psid_field = if psid_len == 0 { 0u16 } else { psid << (16 - psid_len) };
        let mut v = vec![offset, psid_len];
        v.extend_from_slice(&psid_field.to_be_bytes());
        v
    }

    /// OPTION_S46_RULE ペイロードを構築する。
    fn s46_rule_payload(
        flags: u8,
        ea_len: u8,
        ipv4: &str,
        prefix4_len: u8,
        ipv6: &str,
        prefix6_len: u8,
        portparams: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let ipv4_addr: Ipv4Addr = ipv4.parse().unwrap();
        let ipv4_bytes_len = ((prefix4_len as usize) + 7) / 8;
        let ipv6_addr: Ipv6Addr = ipv6.parse().unwrap();
        let ipv6_bytes_len = ((prefix6_len as usize) + 7) / 8;

        let mut v = vec![flags, ea_len, prefix4_len];
        v.extend_from_slice(&ipv4_addr.octets()[..ipv4_bytes_len]);
        v.push(prefix6_len);
        v.extend_from_slice(&ipv6_addr.octets()[..ipv6_bytes_len]);

        if let Some(pp) = portparams {
            v.extend_from_slice(&opt(OPT_S46_PORTPARAMS, &pp));
        }
        v
    }

    /// OPTION_S46_CONT_MAPE コンテナを含む Reply メッセージを構築する。
    fn mape_reply(br: Ipv6Addr, rules: Vec<Vec<u8>>) -> Vec<u8> {
        let br_opt = opt(OPT_S46_BR, &s46_br_payload(br));
        let mut container_payload = br_opt;
        for rule_data in rules {
            container_payload.extend_from_slice(&opt(OPT_S46_RULE, &rule_data));
        }
        let cont = opt(OPT_S46_CONT_MAPE, &container_payload);
        reply_msg(&cont)
    }

    // ────────────────────────────────────────────────────────────────
    // parse_mape_container テスト
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_mape_single_rule() {
        let br: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let pp = s46_portparams_payload(4, 8, 0);
        let rule = s46_rule_payload(0x01, 16, "192.0.2.0", 24, "2001:db8::", 32, Some(pp));
        let msg = mape_reply(br, vec![rule]);

        let result = parse_mape_container(&msg).unwrap().unwrap();
        assert_eq!(result.len(), 1);

        let r = &result[0];
        assert_eq!(r.br_address, br);
        assert!(r.is_fme);
        assert_eq!(r.ea_length, 16);
        assert_eq!(r.ipv4_prefix, Ipv4Net::from_str("192.0.2.0/24").unwrap());
        assert_eq!(r.ipv6_prefix, Ipv6Net::from_str("2001:db8::/32").unwrap());
        assert_eq!(r.port_params, PortParams { psid_offset: 4, psid_length: 8 });
    }

    #[test]
    fn test_parse_mape_multiple_rules() {
        let br: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule1 = s46_rule_payload(0x01, 16, "192.0.2.0", 24, "2001:db8::", 32, None);
        let rule2 = s46_rule_payload(0x01, 8, "203.0.113.0", 24, "2001:db8:1::", 48, None);
        let msg = mape_reply(br, vec![rule1, rule2]);

        let result = parse_mape_container(&msg).unwrap().unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_parse_mape_no_container_returns_none() {
        // OPTION_S46_CONT_MAPE が含まれない通常の Reply
        let msg = reply_msg(&[]);
        let result = parse_mape_container(&msg).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_mape_missing_br_returns_error() {
        // BR オプションなしのコンテナ
        let rule = s46_rule_payload(0x01, 16, "192.0.2.0", 24, "2001:db8::", 32, None);
        let rule_opt = opt(OPT_S46_RULE, &rule);
        let cont = opt(OPT_S46_CONT_MAPE, &rule_opt);
        let msg = reply_msg(&cont);

        let result = parse_mape_container(&msg);
        assert!(matches!(result, Err(MapEError::MissingBrAddress)));
    }

    #[test]
    fn test_parse_mape_no_portparams_uses_default() {
        // OPTION_S46_PORTPARAMS なし → PortParams::default() が使用される
        let br: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = s46_rule_payload(0x00, 8, "192.0.2.0", 24, "2001:db8::", 32, None);
        let msg = mape_reply(br, vec![rule]);

        let result = parse_mape_container(&msg).unwrap().unwrap();
        assert_eq!(result[0].port_params, PortParams::default());
        assert!(!result[0].is_fme); // flags = 0x00
    }

    #[test]
    fn test_parse_mape_ipv4_prefix_length_boundary() {
        // /32 の IPv4 プレフィックス (4 バイト full)
        let br: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = s46_rule_payload(0x01, 0, "192.0.2.1", 32, "2001:db8::", 32, None);
        let msg = mape_reply(br, vec![rule]);

        let result = parse_mape_container(&msg).unwrap().unwrap();
        assert_eq!(result[0].ipv4_prefix, Ipv4Net::from_str("192.0.2.1/32").unwrap());
    }

    #[test]
    fn test_parse_mape_ipv6_prefix_length_40bit() {
        // prefix6-len=40 (5 バイト)
        let br: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = s46_rule_payload(0x01, 16, "192.0.2.0", 24, "2409:250::", 40, None);
        let msg = mape_reply(br, vec![rule]);

        let result = parse_mape_container(&msg).unwrap().unwrap();
        assert_eq!(result[0].ipv6_prefix.prefix_len(), 40);
    }

    #[test]
    fn test_parse_mape_malformed_data_returns_none() {
        // 壊れたデータ → dhcproto パース失敗 → Ok(None)
        let result = parse_mape_container(&[0xFF, 0xAA]).unwrap();
        assert!(result.is_none());
    }

    // ────────────────────────────────────────────────────────────────
    // parse_ia_pd / parse_ia_pd_info テスト
    // ────────────────────────────────────────────────────────────────

    /// IAPREFIX TLV を構築する (dhcproto のフォーマットに合わせる)。
    fn iaprefix_opt(preferred: u32, valid: u32, prefix_len: u8, prefix: Ipv6Addr) -> Vec<u8> {
        // IAPREFIX option (code=26, len=25+sub-opts)
        let mut data = Vec::new();
        data.extend_from_slice(&preferred.to_be_bytes());
        data.extend_from_slice(&valid.to_be_bytes());
        data.push(prefix_len);
        data.extend_from_slice(&prefix.octets());
        // sub-opts なし
        opt(26, &data)
    }

    /// IA_PD オプションを含む Reply を構築する。
    fn iapd_reply(iaid: u32, t1: u32, t2: u32, iaprefix: &[u8]) -> Vec<u8> {
        let mut iapd_data = Vec::new();
        iapd_data.extend_from_slice(&iaid.to_be_bytes());
        iapd_data.extend_from_slice(&t1.to_be_bytes());
        iapd_data.extend_from_slice(&t2.to_be_bytes());
        iapd_data.extend_from_slice(iaprefix);
        let iapd = opt(25, &iapd_data);
        reply_msg(&iapd)
    }

    #[test]
    fn test_parse_ia_pd_basic() {
        let prefix_ip: Ipv6Addr = "2001:db8:6401::".parse().unwrap();
        let iap = iaprefix_opt(1800, 3600, 48, prefix_ip);
        let msg = iapd_reply(1, 900, 1500, &iap);

        let prefix = parse_ia_pd(&msg, None).unwrap();
        assert_eq!(prefix, Ipv6Net::from_str("2001:db8:6401::/48").unwrap());
    }

    #[test]
    fn test_parse_ia_pd_iaid_match() {
        let prefix_ip: Ipv6Addr = "2001:db8:6401::".parse().unwrap();
        let iap = iaprefix_opt(1800, 3600, 48, prefix_ip);
        let msg = iapd_reply(42, 900, 1500, &iap);

        // IAID=42 で一致
        let prefix = parse_ia_pd(&msg, Some(42)).unwrap();
        assert_eq!(prefix.prefix_len(), 48);

        // IAID=1 で不一致 → None
        let none = parse_ia_pd(&msg, Some(1));
        assert!(none.is_none());
    }

    #[test]
    fn test_parse_ia_pd_no_iapd_returns_none() {
        let msg = reply_msg(&[]);
        assert!(parse_ia_pd(&msg, None).is_none());
    }

    #[test]
    fn test_parse_ia_pd_info_t1_t2_zero_complemented() {
        // T1=0, T2=0 → valid_lifetime を基に補完
        let prefix_ip: Ipv6Addr = "2001:db8:6401::".parse().unwrap();
        let iap = iaprefix_opt(1800, 3600, 48, prefix_ip);
        let msg = iapd_reply(1, 0, 0, &iap);

        let info = parse_ia_pd_info(&msg, None).unwrap();
        assert_eq!(info.valid_lifetime, 3600);
        assert_eq!(info.t1, 3600 / 2); // 1800
        assert_eq!(info.t2, 3600 * 4 / 5); // 2880
    }

    #[test]
    fn test_parse_ia_pd_info_t1_t2_explicit() {
        // T1/T2 が明示されている場合はそのまま使用
        let prefix_ip: Ipv6Addr = "2001:db8:6401::".parse().unwrap();
        let iap = iaprefix_opt(1800, 3600, 48, prefix_ip);
        let msg = iapd_reply(1, 900, 1500, &iap);

        let info = parse_ia_pd_info(&msg, None).unwrap();
        assert_eq!(info.t1, 900);
        assert_eq!(info.t2, 1500);
    }

    #[test]
    fn test_parse_ia_pd_info_infinite_lifetime() {
        // valid_lifetime=0xFFFFFFFF の場合 T1/T2 も MAX に補完
        let prefix_ip: Ipv6Addr = "2001:db8:6401::".parse().unwrap();
        let iap = iaprefix_opt(u32::MAX, u32::MAX, 48, prefix_ip);
        let msg = iapd_reply(1, 0, 0, &iap);

        let info = parse_ia_pd_info(&msg, None).unwrap();
        assert_eq!(info.t1, u32::MAX);
        assert_eq!(info.t2, u32::MAX);
        assert_eq!(info.valid_lifetime, u32::MAX);
    }
}
