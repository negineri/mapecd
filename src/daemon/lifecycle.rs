//! MAP-E 設定ライフサイクル管理（Linux 専用、ステップ 8-2）
//!
//! ## apply
//! sysctl → CE IPv6 /128 付与 → ip6tnl 作成 → CE IPv4 /32 付与 →
//! IPv4 デフォルトルート → nftables ルールセット
//!
//! ## update
//! 変化フィールドに応じた最小差分更新:
//! - `ce_ipv6` 変化: Steps 2〜6
//! - `br_address` 変化: Steps 3〜6
//! - `ce_ipv4` 変化: Steps 4〜6
//! - `port_ranges` のみ変化: Step 6
//!
//! ## cleanup
//! apply の逆順で設定を削除

use crate::{
    config::Config,
    daemon::state::DaemonState,
    error::MapEError,
    map::{port_set::calc_port_ranges, rule::MapeParams},
    netlink::NetlinkHandle,
    nftables::manager::{apply_ruleset, delete_tables, CommandExecutor},
};

// ────────────────────────────────────────────────────────────
// sysctl ヘルパー
// ────────────────────────────────────────────────────────────

const SYSCTL_IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const SYSCTL_IPV6_FORWARD_ALL: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

fn read_sysctl(path: &str) -> Result<String, MapEError> {
    std::fs::read_to_string(path)
        .map(|s| s.trim_end().to_string())
        .map_err(|e| MapEError::NetlinkError(format!("read sysctl {path}: {e}")))
}

fn write_sysctl(path: &str, value: &str) -> Result<(), MapEError> {
    std::fs::write(path, value)
        .map_err(|e| MapEError::NetlinkError(format!("write sysctl {path}={value}: {e}")))
}

// ────────────────────────────────────────────────────────────
// apply（ステップ 8-2）
// ────────────────────────────────────────────────────────────

/// MAP-E 設定を全て適用する。
///
/// 失敗した場合は呼び出し元で即座に `cleanup` を呼ぶこと。
pub async fn apply(
    state: &mut DaemonState,
    config: &Config,
    params: &MapeParams,
    nl: &mut impl NetlinkHandle,
    executor: &impl CommandExecutor,
) -> Result<(), MapEError> {
    // Step 1: sysctl（保存→書き込みの順で実行し cleanup 時の復元範囲を最大化）
    let orig_ipv4 = read_sysctl(SYSCTL_IPV4_FORWARD)?;
    state.original_ip_forward = Some(orig_ipv4);
    write_sysctl(SYSCTL_IPV4_FORWARD, "1")?;

    let orig_ipv6 = read_sysctl(SYSCTL_IPV6_FORWARD_ALL)?;
    state.original_ipv6_forward = Some(orig_ipv6);
    write_sysctl(SYSCTL_IPV6_FORWARD_ALL, "1")?;

    // Step 2: CE IPv6 /128 付与
    apply_step2_add_ipv6(state, config, params, nl).await?;

    // Step 3: ip6tnl トンネル作成
    apply_step3_create_tunnel(state, config, params, nl).await?;

    let tunnel_ifindex = state.tunnel_ifindex.ok_or_else(|| {
        MapEError::NetlinkError("tunnel_ifindex not set after create".to_string())
    })?;

    // Step 4: CE IPv4 /32 付与（トンネル作成後）
    nl.add_ipv4_addr(tunnel_ifindex, params.ipv4).await?;

    // Step 5: IPv4 デフォルトルート追加（add_ipv4_default_route が既存ルートを削除してから追加）
    nl.add_ipv4_default_route(tunnel_ifindex).await?;

    // Step 6: nftables ルールセット適用
    apply_step6_nftables(config, params, executor).await?;

    Ok(())
}

// ────────────────────────────────────────────────────────────
// update（ステップ 8-2）
// ────────────────────────────────────────────────────────────

/// 差分のみを更新する。変化がない場合は何もしない（呼び出し元で判断済み）。
///
/// 失敗した場合は呼び出し元で `cleanup` を呼ぶこと。
pub async fn update(
    state: &mut DaemonState,
    config: &Config,
    old: &MapeParams,
    new: &MapeParams,
    nl: &mut impl NetlinkHandle,
    executor: &impl CommandExecutor,
) -> Result<(), MapEError> {
    if old.ce_ipv6 != new.ce_ipv6 {
        // Steps 2〜6: ce_ipv6 が変化した場合は upstream の /128 アドレスも更新
        let upstream_ifindex = nl.get_link_index(&config.upstream_interface).await?;

        // 旧 /128 削除 → 新 /128 付与
        if let Err(e) = nl.del_ipv6_addr(upstream_ifindex, old.ce_ipv6).await {
            tracing::warn!("del old IPv6 /128 {}: {e}", old.ce_ipv6);
        }
        nl.add_ipv6_addr(upstream_ifindex, new.ce_ipv6).await?;

        // トンネル delete → create → Steps 4〜6
        recreate_tunnel_and_apply(state, config, new, nl, executor).await?;
    } else if old.br_address != new.br_address {
        // Steps 3〜6: br_address のみ変化
        recreate_tunnel_and_apply(state, config, new, nl, executor).await?;
    } else if old.ipv4 != new.ipv4 {
        // Steps 4〜6: ce_ipv4 のみ変化
        let tunnel_ifindex = state.tunnel_ifindex.ok_or_else(|| {
            MapEError::NetlinkError("tunnel_ifindex not set for IPv4 addr update".to_string())
        })?;

        if let Err(e) = nl.del_ipv4_addr(tunnel_ifindex, old.ipv4).await {
            tracing::warn!("del old IPv4 /32 {}: {e}", old.ipv4);
        }
        nl.add_ipv4_addr(tunnel_ifindex, new.ipv4).await?;
        nl.add_ipv4_default_route(tunnel_ifindex).await?;
        apply_step6_nftables(config, new, executor).await?;
    } else {
        // port_ranges のみ変化: Step 6 のみ
        apply_step6_nftables(config, new, executor).await?;
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────
// cleanup（ステップ 8-2）
// ────────────────────────────────────────────────────────────

/// apply の逆順で設定を削除する。
///
/// 各ステップの失敗は warn ログで続行する（部分的クリーンアップを最大化）。
pub async fn cleanup(
    state: &mut DaemonState,
    config: &Config,
    params: &MapeParams,
    nl: &mut impl NetlinkHandle,
    executor: &impl CommandExecutor,
) {
    let tunnel_ifindex = state.tunnel_ifindex;

    // Step 1: nftables テーブル削除
    if let Err(e) = delete_tables(executor).await {
        tracing::warn!("delete nftables tables failed: {e}");
    }

    // Step 2: IPv4 デフォルトルート削除（トンネル oif でフィルタ）
    if let Some(oif) = tunnel_ifindex {
        if let Err(e) = nl.del_ipv4_default_route_by_oif(oif).await {
            tracing::warn!("del default route oif={oif} failed: {e}");
        }
    }

    // Step 3: ip6tnl トンネル削除
    if let Some(oif) = tunnel_ifindex {
        if let Err(e) = nl.delete_link(oif).await {
            tracing::warn!("delete tunnel ifindex={oif} failed: {e}");
        }
        state.tunnel_ifindex = None;
    }

    // Step 4: CE IPv4 /32 削除（トンネル削除と同時に消滅するが統一性のため実行）
    // del_ipv4_addr は ENODEV を warn で無視する
    if let Some(oif) = tunnel_ifindex {
        if let Err(e) = nl.del_ipv4_addr(oif, params.ipv4).await {
            tracing::warn!("del IPv4 addr {} failed: {e}", params.ipv4);
        }
    }

    // Step 5: CE IPv6 /128 削除
    match nl.get_link_index(&config.upstream_interface).await {
        Ok(upstream_ifindex) => {
            if let Err(e) = nl.del_ipv6_addr(upstream_ifindex, params.ce_ipv6).await {
                tracing::warn!("del IPv6 addr {} failed: {e}", params.ce_ipv6);
            }
        }
        Err(e) => {
            tracing::warn!("get upstream ifindex for IPv6 cleanup failed: {e}");
        }
    }

    // Step 6: sysctl 復元（逆順: ipv6 → ipv4）
    if let Some(v) = state.original_ipv6_forward.take() {
        if let Err(e) = write_sysctl(SYSCTL_IPV6_FORWARD_ALL, &v) {
            tracing::warn!("restore sysctl {SYSCTL_IPV6_FORWARD_ALL}={v} failed: {e}");
        }
    }
    if let Some(v) = state.original_ip_forward.take() {
        if let Err(e) = write_sysctl(SYSCTL_IPV4_FORWARD, &v) {
            tracing::warn!("restore sysctl {SYSCTL_IPV4_FORWARD}={v} failed: {e}");
        }
    }
}

// ────────────────────────────────────────────────────────────
// 内部ヘルパー
// ────────────────────────────────────────────────────────────

/// Step 2: CE IPv6 /128 付与
async fn apply_step2_add_ipv6(
    _state: &mut DaemonState,
    config: &Config,
    params: &MapeParams,
    nl: &mut impl NetlinkHandle,
) -> Result<(), MapEError> {
    let upstream_ifindex = nl.get_link_index(&config.upstream_interface).await?;
    nl.add_ipv6_addr(upstream_ifindex, params.ce_ipv6).await
}

/// Step 3: ip6tnl トンネル作成
async fn apply_step3_create_tunnel(
    state: &mut DaemonState,
    config: &Config,
    params: &MapeParams,
    nl: &mut impl NetlinkHandle,
) -> Result<(), MapEError> {
    let upstream_ifindex = nl.get_link_index(&config.upstream_interface).await?;
    let mtu = match config.tunnel_mtu {
        Some(m) => m,
        None => nl
            .get_link_mtu(&config.upstream_interface)
            .await?
            .saturating_sub(40)
            .max(1280),
    };
    let tunnel_ifindex = nl
        .create_ip6tnl(
            &config.tunnel_interface,
            params.ce_ipv6,
            params.br_address,
            upstream_ifindex,
            mtu,
        )
        .await?;
    state.tunnel_ifindex = Some(tunnel_ifindex);
    Ok(())
}

/// Step 6: nftables ルールセット適用
async fn apply_step6_nftables(
    config: &Config,
    params: &MapeParams,
    executor: &impl CommandExecutor,
) -> Result<(), MapEError> {
    let port_ranges = calc_port_ranges(&params.rule.port_params, params.psid);
    apply_ruleset(executor, &port_ranges, &config.tunnel_interface, params.br_address).await
}

/// トンネル delete → create → Step 4〜6 を実行する（update 共通処理）
async fn recreate_tunnel_and_apply(
    state: &mut DaemonState,
    config: &Config,
    new: &MapeParams,
    nl: &mut impl NetlinkHandle,
    executor: &impl CommandExecutor,
) -> Result<(), MapEError> {
    // 旧トンネル削除
    if let Some(oif) = state.tunnel_ifindex {
        if let Err(e) = nl.del_ipv4_default_route_by_oif(oif).await {
            tracing::warn!("del route before tunnel recreate: {e}");
        }
        nl.delete_link(oif).await?;
        state.tunnel_ifindex = None;
    }

    // 新トンネル作成
    apply_step3_create_tunnel(state, config, new, nl).await?;

    let tunnel_ifindex = state.tunnel_ifindex.ok_or_else(|| {
        MapEError::NetlinkError("tunnel_ifindex not set after recreate".to_string())
    })?;

    // CE IPv4 /32 付与
    nl.add_ipv4_addr(tunnel_ifindex, new.ipv4).await?;

    // IPv4 デフォルトルート
    nl.add_ipv4_default_route(tunnel_ifindex).await?;

    // nftables
    apply_step6_nftables(config, new, executor).await
}

// ────────────────────────────────────────────────────────────
// params 変化検出ヘルパー
// ────────────────────────────────────────────────────────────

/// 2 つの `MapeParams` を比較して変化があるかどうかを返す。
///
/// `rule` フィールドは同一 MAP ルール・CE プレフィックスから導出されるため
/// 比較対象から除外し、適用結果に影響するフィールドのみを比較する。
pub fn has_changed(old: &MapeParams, new: &MapeParams) -> bool {
    old.ce_ipv6 != new.ce_ipv6
        || old.ipv4 != new.ipv4
        || old.psid != new.psid
        || old.br_address != new.br_address
        || old.port_ranges != new.port_ranges
}

// ────────────────────────────────────────────────────────────
// テスト（mock を使用した状態遷移テスト）
// ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        ops::RangeInclusive,
        sync::{Arc, Mutex},
    };

    use ipnet::Ipv6Net;

    use super::*;
    use crate::{
        error::MapEError,
        map::rule::{MapRule, MapeParams, PortParams},
        netlink::NetlinkHandle,
        nftables::manager::CommandExecutor,
    };

    // ─── Mock NetlinkHandle ──────────────────────────────────

    #[derive(Default)]
    struct MockNl {
        pub added_v6: Vec<(u32, Ipv6Addr)>,
        pub deleted_v6: Vec<(u32, Ipv6Addr)>,
        pub added_v4: Vec<(u32, Ipv4Addr)>,
        pub deleted_v4: Vec<(u32, Ipv4Addr)>,
        pub created_tunnels: Vec<String>,
        pub deleted_links: Vec<u32>,
        pub added_routes: Vec<u32>,
        pub deleted_routes: Vec<u32>,
        pub link_mtu: u32,
        pub link_index: u32,
        pub tunnel_ifindex_counter: u32,
    }

    impl MockNl {
        fn new() -> Self {
            Self {
                link_mtu: 1500,
                link_index: 3,
                tunnel_ifindex_counter: 10,
                ..Default::default()
            }
        }
    }

    impl NetlinkHandle for MockNl {
        async fn add_ipv6_addr(&mut self, ifindex: u32, addr: Ipv6Addr) -> Result<(), MapEError> {
            self.added_v6.push((ifindex, addr));
            Ok(())
        }
        async fn del_ipv6_addr(&mut self, ifindex: u32, addr: Ipv6Addr) -> Result<(), MapEError> {
            self.deleted_v6.push((ifindex, addr));
            Ok(())
        }
        async fn add_ipv4_addr(&mut self, ifindex: u32, addr: Ipv4Addr) -> Result<(), MapEError> {
            self.added_v4.push((ifindex, addr));
            Ok(())
        }
        async fn del_ipv4_addr(&mut self, ifindex: u32, addr: Ipv4Addr) -> Result<(), MapEError> {
            self.deleted_v4.push((ifindex, addr));
            Ok(())
        }
        async fn get_link_mtu(&mut self, _: &str) -> Result<u32, MapEError> {
            Ok(self.link_mtu)
        }
        async fn get_link_index(&mut self, _: &str) -> Result<u32, MapEError> {
            Ok(self.link_index)
        }
        async fn create_ip6tnl(
            &mut self,
            name: &str,
            _: Ipv6Addr,
            _: Ipv6Addr,
            _: u32,
            _: u32,
        ) -> Result<u32, MapEError> {
            self.created_tunnels.push(name.to_string());
            let idx = self.tunnel_ifindex_counter;
            self.tunnel_ifindex_counter += 1;
            Ok(idx)
        }
        async fn delete_link(&mut self, ifindex: u32) -> Result<(), MapEError> {
            self.deleted_links.push(ifindex);
            Ok(())
        }
        async fn get_ipv4_default_routes(&mut self) -> Result<Vec<u32>, MapEError> {
            Ok(vec![])
        }
        async fn add_ipv4_default_route(&mut self, oif: u32) -> Result<(), MapEError> {
            self.added_routes.push(oif);
            Ok(())
        }
        async fn del_ipv4_default_route_by_oif(&mut self, oif: u32) -> Result<(), MapEError> {
            self.deleted_routes.push(oif);
            Ok(())
        }
    }

    // ─── Mock CommandExecutor ────────────────────────────────

    #[derive(Default)]
    struct MockExecutor {
        pub calls: Arc<Mutex<Vec<String>>>,
    }

    impl CommandExecutor for MockExecutor {
        async fn execute(&self, input: &str) -> Result<(), MapEError> {
            self.calls.lock().unwrap().push(input.to_string());
            Ok(())
        }
    }

    // ─── テスト用ヘルパー ─────────────────────────────────────

    fn make_config() -> Config {
        Config {
            upstream_interface: "eth0".to_string(),
            tunnel_interface: "ip6tnl0".to_string(),
            tunnel_mtu: None,
            pid_file: "/run/mapecd.pid".into(),
            map_rules_cache_file: "/run/mapecd/rules.cache".into(),
            duid_file: "/var/lib/mapecd/duid".into(),
            dhcpv6_mode: crate::config::DhcpV6Mode::Capture,
        }
    }

    fn make_params(
        ce_ipv6: &str,
        ipv4: &str,
        br: &str,
        psid: u16,
    ) -> MapeParams {
        MapeParams {
            ce_ipv6: ce_ipv6.parse().unwrap(),
            ipv4: ipv4.parse().unwrap(),
            psid,
            port_ranges: vec![1u16..=65535u16],
            br_address: br.parse().unwrap(),
            rule: MapRule {
                ipv6_prefix: "2001:db8::/32".parse().unwrap(),
                ipv4_prefix: "192.0.2.0/24".parse().unwrap(),
                ea_length: 40,
                is_fme: true,
                br_address: br.parse().unwrap(),
                port_params: PortParams { psid_offset: 0, psid_length: 0 },
            },
        }
    }

    // ─── has_changed テスト ───────────────────────────────────

    #[test]
    fn test_has_changed_same_params() {
        let p = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        assert!(!has_changed(&p, &p));
    }

    #[test]
    fn test_has_changed_ce_ipv6() {
        let old = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let new = make_params("2001:db8::2", "192.0.2.1", "2001:db8::ff", 0);
        assert!(has_changed(&old, &new));
    }

    #[test]
    fn test_has_changed_ipv4() {
        let old = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let new = make_params("2001:db8::1", "192.0.2.2", "2001:db8::ff", 0);
        assert!(has_changed(&old, &new));
    }

    #[test]
    fn test_has_changed_br_address() {
        let old = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let new = make_params("2001:db8::1", "192.0.2.1", "2001:db8::fe", 0);
        assert!(has_changed(&old, &new));
    }

    // ─── apply テスト（mock によるステップ確認）──────────────

    #[tokio::test]
    async fn test_apply_sets_tunnel_ifindex() {
        let config = make_config();
        let params = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let mut state = DaemonState::new();
        let mut nl = MockNl::new();
        let executor = MockExecutor::default();

        // sysctl 操作はモックなし（Linux でのみ実際に実行）
        // lifecycle::apply のステップ 1 は Linux 専用パスのため
        // テストではダミーで保存済みとしてスキップ
        // 代わりに steps 2〜6 のみをテスト

        // state に sysctl 保存済みを模擬
        state.original_ip_forward = Some("0".to_string());
        state.original_ipv6_forward = Some("0".to_string());

        // steps 2〜6 を直接実行（apply のうち sysctl 以外）
        apply_step2_add_ipv6(&mut state, &config, &params, &mut nl).await.unwrap();
        apply_step3_create_tunnel(&mut state, &config, &params, &mut nl).await.unwrap();
        let tidx = state.tunnel_ifindex.unwrap();
        nl.add_ipv4_addr(tidx, params.ipv4).await.unwrap();
        nl.add_ipv4_default_route(tidx).await.unwrap();
        apply_step6_nftables(&config, &params, &executor).await.unwrap();

        assert_eq!(state.tunnel_ifindex, Some(10));
        assert_eq!(nl.created_tunnels, vec!["ip6tnl0"]);
        assert_eq!(nl.added_routes, vec![10]);
        assert!(!executor.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_clears_state() {
        let config = make_config();
        let params = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let mut state = DaemonState::new();
        state.tunnel_ifindex = Some(10);
        state.original_ip_forward = Some("0".to_string());
        state.original_ipv6_forward = Some("0".to_string());
        let mut nl = MockNl::new();
        let executor = MockExecutor::default();

        cleanup(&mut state, &config, &params, &mut nl, &executor).await;

        assert!(state.tunnel_ifindex.is_none());
        assert!(state.original_ip_forward.is_none());
        assert!(state.original_ipv6_forward.is_none());
        assert!(nl.deleted_links.contains(&10));
    }

    #[tokio::test]
    async fn test_cleanup_without_tunnel_does_not_panic() {
        let config = make_config();
        let params = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let mut state = DaemonState::new();
        // tunnel_ifindex が None（apply 前に cleanup が呼ばれた場合）
        let mut nl = MockNl::new();
        let executor = MockExecutor::default();

        cleanup(&mut state, &config, &params, &mut nl, &executor).await;
        // パニックなく完了すること
    }

    #[tokio::test]
    async fn test_update_ce_ipv6_change_recreates_tunnel() {
        let config = make_config();
        let old = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let new = make_params("2001:db8::2", "192.0.2.2", "2001:db8::ff", 0);
        let mut state = DaemonState::new();
        state.tunnel_ifindex = Some(10);
        let mut nl = MockNl::new();
        let executor = MockExecutor::default();

        update(&mut state, &config, &old, &new, &mut nl, &executor)
            .await
            .unwrap();

        // 旧 IPv6 アドレスが削除されること
        assert!(nl.deleted_v6.iter().any(|(_, a)| *a == old.ce_ipv6));
        // 新 IPv6 アドレスが追加されること
        assert!(nl.added_v6.iter().any(|(_, a)| *a == new.ce_ipv6));
        // 旧トンネルが削除されること
        assert!(nl.deleted_links.contains(&10));
        // 新トンネルが作成されること
        assert!(!nl.created_tunnels.is_empty());
    }

    #[tokio::test]
    async fn test_update_port_ranges_only_calls_nftables() {
        let config = make_config();
        let mut old = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 0);
        let mut new = make_params("2001:db8::1", "192.0.2.1", "2001:db8::ff", 5);
        // port_ranges を変化させる
        old.port_ranges = vec![1u16..=65535u16];
        new.port_ranges = vec![4101u16..=4356u16];
        let mut state = DaemonState::new();
        state.tunnel_ifindex = Some(10);
        let mut nl = MockNl::new();
        let executor = MockExecutor::default();

        update(&mut state, &config, &old, &new, &mut nl, &executor)
            .await
            .unwrap();

        // トンネル操作は発生しないこと
        assert!(nl.created_tunnels.is_empty());
        assert!(nl.deleted_links.is_empty());
        // nftables のみ更新されること
        assert!(!executor.calls.lock().unwrap().is_empty());
    }
}
