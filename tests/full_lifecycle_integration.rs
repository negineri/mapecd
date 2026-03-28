#![cfg(target_os = "linux")]

mod common;

use common::netns::TestNetNs;
use mapecd::config::{Config, DhcpV6Mode};
use mapecd::daemon::lifecycle;
use mapecd::daemon::state::DaemonState;
use mapecd::map::port_set::calc_port_ranges;
use mapecd::map::rule::{CeFormat, MapRule, MapeParams, PortParams};
use mapecd::netlink::{NetlinkHandle, RtNetlinkHandle};
use mapecd::nftables::manager::NftExecutor;

fn make_config() -> Config {
    Config {
        upstream_interface: "lo".to_string(),
        tunnel_interface: "mapecd0".to_string(),
        tunnel_mtu: Some(1460),
        pid_file: "/tmp/mapecd-test.pid".into(),
        map_rules_cache_file: "/tmp/mapecd-test-rules.cache".into(),
        duid_file: "/tmp/mapecd-test-duid".into(),
        dhcpv6_mode: DhcpV6Mode::Capture,
        use_v6plus_static_rules: false,
    }
}

fn make_port_params() -> PortParams {
    PortParams {
        psid_offset: 4,  // a=4
        psid_length: 8,  // k=8
    }
}

fn make_map_rule(br: &str) -> MapRule {
    MapRule {
        ipv6_prefix: "2001:db8::/32".parse().unwrap(),
        ipv4_prefix: "192.0.2.0/24".parse().unwrap(),
        ea_length: 20,
        is_fmr: true,
        br_address: br.parse().unwrap(),
        port_params: make_port_params(),
    }
}

fn make_params(
    ce_ipv6: &str,
    ipv4: &str,
    psid: u16,
    br: &str,
) -> MapeParams {
    let rule = make_map_rule(br);
    let port_ranges = calc_port_ranges(&rule.port_params, psid);
    MapeParams {
        ce_ipv6: ce_ipv6.parse().unwrap(),
        ipv4: ipv4.parse().unwrap(),
        psid,
        port_ranges,
        br_address: br.parse().unwrap(),
        rule,
        ce_format: CeFormat::Rfc7597,
    }
}

/// lifecycle::apply が Network Namespace 内で正常に動作することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_apply_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);
        let executor = NftExecutor;
        let config = make_config();
        let params = make_params(
            "2001:db8::1",
            "192.0.2.1",
            5,
            "2001:db8:ff::1",
        );
        let mut state = DaemonState::new();

        let result = lifecycle::apply(&mut state, &config, &params, &mut nl, &executor).await;

        // nft や sysctl で権限不足になる場合はスキップ
        if let Err(ref e) = result {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
                eprintln!("Skipping: insufficient privileges ({msg})");
                return Ok(());
            }
        }
        result.expect("lifecycle::apply failed");

        // トンネルの ifindex が設定されていることを確認する
        assert!(state.tunnel_ifindex.is_some(), "tunnel_ifindex should be set after apply");

        // cleanup で後片付けする
        lifecycle::cleanup(&mut state, &config, &params, &mut nl, &executor).await;

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// ce_ipv6 が変化した場合に lifecycle::update がトンネルを再作成することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_update_ce_ipv6_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);
        let executor = NftExecutor;
        let config = make_config();
        let old_params = make_params("2001:db8::1", "192.0.2.1", 5, "2001:db8:ff::1");
        let new_params = make_params("2001:db8::2", "192.0.2.2", 6, "2001:db8:ff::1");
        let mut state = DaemonState::new();

        // apply を実行する
        let result = lifecycle::apply(&mut state, &config, &old_params, &mut nl, &executor).await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
                eprintln!("Skipping: insufficient privileges ({msg})");
                return Ok(());
            }
        }
        result.expect("lifecycle::apply failed");

        let old_tunnel_ifindex = state.tunnel_ifindex.expect("tunnel_ifindex should be set");

        // update を実行する（ce_ipv6 変化）
        lifecycle::update(&mut state, &config, &old_params, &new_params, &mut nl, &executor)
            .await
            .expect("lifecycle::update failed");

        // トンネルが再作成されていること（ifindex が変化）
        let new_tunnel_ifindex = state.tunnel_ifindex.expect("tunnel_ifindex should be set after update");
        assert_ne!(
            old_tunnel_ifindex, new_tunnel_ifindex,
            "tunnel ifindex should change after ce_ipv6 update"
        );

        // cleanup で後片付けする
        lifecycle::cleanup(&mut state, &config, &new_params, &mut nl, &executor).await;

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// port_ranges のみ変化した場合に lifecycle::update が nftables のみ更新することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_update_port_ranges_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);
        let executor = NftExecutor;
        let config = make_config();
        let old_params = make_params("2001:db8::1", "192.0.2.1", 5, "2001:db8:ff::1");
        let new_params = make_params("2001:db8::1", "192.0.2.1", 6, "2001:db8:ff::1");
        let mut state = DaemonState::new();

        // apply を実行する
        let result = lifecycle::apply(&mut state, &config, &old_params, &mut nl, &executor).await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
                eprintln!("Skipping: insufficient privileges ({msg})");
                return Ok(());
            }
        }
        result.expect("lifecycle::apply failed");

        let tunnel_ifindex_before = state.tunnel_ifindex.expect("tunnel_ifindex should be set");

        // update を実行する（port_ranges のみ変化: psid 変化だが ipv4 同一）
        lifecycle::update(&mut state, &config, &old_params, &new_params, &mut nl, &executor)
            .await
            .expect("lifecycle::update failed");

        // トンネルの ifindex は変化しないことを確認する
        let tunnel_ifindex_after = state.tunnel_ifindex.expect("tunnel_ifindex should remain set");
        assert_eq!(
            tunnel_ifindex_before, tunnel_ifindex_after,
            "tunnel ifindex should not change for port_ranges-only update"
        );

        // cleanup で後片付けする
        lifecycle::cleanup(&mut state, &config, &new_params, &mut nl, &executor).await;

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// lifecycle::cleanup が apply 後に正常に動作することを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_lifecycle_cleanup_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);
        let executor = NftExecutor;
        let config = make_config();
        let params = make_params("2001:db8::1", "192.0.2.1", 5, "2001:db8:ff::1");
        let mut state = DaemonState::new();

        // apply を実行する
        let result = lifecycle::apply(&mut state, &config, &params, &mut nl, &executor).await;
        if let Err(ref e) = result {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
                eprintln!("Skipping: insufficient privileges ({msg})");
                return Ok(());
            }
        }
        result.expect("lifecycle::apply failed");

        assert!(state.tunnel_ifindex.is_some(), "tunnel should exist after apply");

        // cleanup を実行する
        lifecycle::cleanup(&mut state, &config, &params, &mut nl, &executor).await;

        // state がクリアされていることを確認する
        assert!(state.tunnel_ifindex.is_none(), "tunnel_ifindex should be None after cleanup");
        assert!(state.original_ip_forward.is_none(), "original_ip_forward should be None after cleanup");
        assert!(state.original_ipv6_forward.is_none(), "original_ipv6_forward should be None after cleanup");

        // トンネルインターフェースが削除されていることを確認する
        let result = nl.get_link_index("mapecd0").await;
        assert!(result.is_err(), "tunnel interface should not exist after cleanup");

        Ok(())
    })
    .await
    .expect("netns run failed");
}
