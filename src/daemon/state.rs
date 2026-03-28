//! デーモン状態管理
//!
//! `DaemonState` は MAP Rule と IA_PD の最新スナップショットを保持し、
//! 両方が揃った時点で `MapeParams` を計算する。

use ipnet::Ipv6Net;

use crate::{
    ebpf::EbpfManager,
    error::MapEError,
    map::{
        calc::compute_mape_params,
        rule::{CeFormat, MapRule, MapeParams},
    },
};

/// デーモンの実行時状態。
///
/// `pending_map_rules` と `pending_ia_pd` が両方揃うと
/// `try_compute` によって `params` が更新される。
///
/// 型パラメータ `E` は eBPF マネージャの型（本番: `EbpfManager`、テスト: `MockEbpfHandle`）。
pub struct DaemonState<E = EbpfManager> {
    /// DHCPv6 サーバーから受信した MAP ルール群（キャッシュ復元を含む）。
    pub pending_map_rules: Option<Vec<MapRule>>,
    /// IA_PD で割り当てられた CE プレフィックス。
    pub pending_ia_pd: Option<Ipv6Net>,
    /// 計算済み MAP-E パラメータ（apply 済みのパラメータ）。
    pub params: Option<MapeParams>,
    /// ip6tnl トンネルの ifindex（create_ip6tnl 後に設定）。
    pub tunnel_ifindex: Option<u32>,
    /// ip_forward の元の値（cleanup 時に復元するため保存）。
    pub original_ip_forward: Option<String>,
    /// ipv6/conf/all/forwarding の元の値（cleanup 時に復元するため保存）。
    pub original_ipv6_forward: Option<String>,
    /// eBPF マネージャ（TC フィルタ管理）。Linux 専用。
    pub ebpf: Option<E>,
}

impl<E> Default for DaemonState<E> {
    fn default() -> Self {
        Self {
            pending_map_rules: None,
            pending_ia_pd: None,
            params: None,
            tunnel_ifindex: None,
            original_ip_forward: None,
            original_ipv6_forward: None,
            ebpf: None,
        }
    }
}

impl<E> DaemonState<E> {
    pub fn new() -> Self {
        Self::default()
    }

    /// `pending_map_rules` と `pending_ia_pd` から `MapeParams` を計算する。
    ///
    /// # 戻り値
    ///
    /// - `Ok(true)`: 計算成功、`self.params` を更新した。
    /// - `Ok(false)`: 情報が不足しているため計算をスキップした。
    /// - `Err(NoPrefixMatch)`: マッチするルールが存在しない。
    /// - `Err(...)`: `compute_mape_params` のその他エラー。
    pub fn try_compute(&mut self, format: CeFormat) -> Result<bool, MapEError> {
        let rules = match &self.pending_map_rules {
            Some(r) if !r.is_empty() => r,
            _ => return Ok(false),
        };
        let ce_prefix = match self.pending_ia_pd {
            Some(p) => p,
            None => return Ok(false),
        };

        for rule in rules {
            if !rule.ipv6_prefix.contains(&ce_prefix.addr()) {
                continue;
            }
            match compute_mape_params(ce_prefix, rule, format) {
                Ok(p) => {
                    self.params = Some(p);
                    return Ok(true);
                }
                Err(e) => {
                    tracing::warn!(
                        rule_prefix = %rule.ipv6_prefix,
                        "compute_mape_params failed: {e}"
                    );
                    // 次のルールを試す
                }
            }
        }

        Err(MapEError::NoPrefixMatch)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;
    use crate::map::rule::{CeFormat, PortParams};

    // 型パラメータ E を使わないテスト用の型エイリアス
    type TestState = DaemonState<()>;

    fn make_rule(ipv6_prefix: &str, ipv4_prefix: &str, ea_length: u8) -> MapRule {
        MapRule {
            ipv6_prefix: ipv6_prefix.parse().unwrap(),
            ipv4_prefix: ipv4_prefix.parse().unwrap(),
            ea_length,
            is_fmr: true,
            br_address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            port_params: PortParams { psid_offset: 4, psid_length: 8 },
        }
    }

    #[test]
    fn test_try_compute_no_rules() {
        let mut state = TestState::new();
        state.pending_ia_pd = Some("2001:db8:0:1::/64".parse().unwrap());
        assert_eq!(state.try_compute(CeFormat::Rfc7597).unwrap(), false);
        assert!(state.params.is_none());
    }

    #[test]
    fn test_try_compute_no_ia_pd() {
        let mut state = TestState::new();
        state.pending_map_rules = Some(vec![make_rule("2001:db8::/32", "192.0.2.0/24", 40)]);
        assert_eq!(state.try_compute(CeFormat::Rfc7597).unwrap(), false);
        assert!(state.params.is_none());
    }

    #[test]
    fn test_try_compute_no_match() {
        let mut state = TestState::new();
        state.pending_map_rules = Some(vec![make_rule("2001:db8::/32", "192.0.2.0/24", 40)]);
        // ce_prefix が rule と一致しない
        state.pending_ia_pd = Some("2001:db9::/48".parse().unwrap());
        assert!(matches!(state.try_compute(CeFormat::Rfc7597), Err(MapEError::NoPrefixMatch)));
    }

    #[test]
    fn test_try_compute_success() {
        // Rule IPv6: 2001:db8::/32, ea_length=16 → CE prefix /48 が一致する
        // CE prefix: 2001:db8:6405::/48 → IPv4=192.0.2.100, PSID=5
        let mut state = TestState::new();
        state.pending_map_rules =
            Some(vec![make_rule("2001:db8::/32", "192.0.2.0/24", 16)]);
        state.pending_ia_pd = Some("2001:db8:6405::/48".parse().unwrap());

        assert_eq!(state.try_compute(CeFormat::Rfc7597).unwrap(), true);
        let params = state.params.as_ref().unwrap();
        assert_eq!(
            params.ipv4,
            "192.0.2.100".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(params.psid, 5);
        assert_eq!(params.ce_format, CeFormat::Rfc7597);
    }
}
