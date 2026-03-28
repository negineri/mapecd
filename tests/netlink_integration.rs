#![cfg(target_os = "linux")]

mod common;

use common::netns::TestNetNs;
use mapecd::netlink::RtNetlinkHandle;
use mapecd::netlink::NetlinkHandle;

/// ip6tnl トンネルの作成・削除を Network Namespace 内で検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_create_and_delete_ip6tnl_tunnel() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);

        // lo の ifindex を取得する
        let lo_index = nl.get_link_index("lo").await
            .expect("get lo ifindex failed");

        // ip6tnl トンネルを作成する
        let local: std::net::Ipv6Addr = "::1".parse().unwrap();
        let remote: std::net::Ipv6Addr = "::2".parse().unwrap();
        let ifindex = nl
            .create_ip6tnl("mapecd-test0", local, remote, lo_index, 1500)
            .await
            .expect("create_ip6tnl failed");

        assert!(ifindex > 0, "ifindex should be > 0");

        // インターフェースが存在することを確認する
        let found = nl
            .get_link_index("mapecd-test0")
            .await
            .expect("get_link_index after create failed");
        assert_eq!(found, ifindex);

        // トンネルを削除する
        nl.delete_link(ifindex).await.expect("delete_link failed");

        // 削除後は見つからないことを確認する
        let result = nl.get_link_index("mapecd-test0").await;
        assert!(result.is_err(), "interface should not exist after deletion");

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// IPv4 アドレスの付与・削除を Network Namespace 内で検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_add_del_ipv4_addr() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);

        // lo に IPv4 アドレスを付与する（lo は常に存在する）
        let lo_index = nl.get_link_index("lo").await
            .expect("get lo ifindex failed");

        let addr: std::net::Ipv4Addr = "192.0.2.1".parse().unwrap();

        nl.add_ipv4_addr(lo_index, addr).await
            .expect("add_ipv4_addr failed");

        // アドレスが付与されていることを確認する
        nl.del_ipv4_addr(lo_index, addr).await
            .expect("del_ipv4_addr failed");

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// IPv6 アドレスの付与・削除を Network Namespace 内で検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_add_del_ipv6_addr() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);

        let lo_index = nl.get_link_index("lo").await
            .expect("get lo ifindex failed");

        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();

        nl.add_ipv6_addr(lo_index, addr).await
            .expect("add_ipv6_addr failed");

        nl.del_ipv6_addr(lo_index, addr).await
            .expect("del_ipv6_addr failed");

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// IPv4 デフォルトルートの追加を Network Namespace 内で検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_add_ipv4_default_route() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);

        let lo_index = nl.get_link_index("lo").await
            .expect("get lo ifindex failed");

        // デフォルトルートを追加する
        nl.add_ipv4_default_route(lo_index).await
            .expect("add_ipv4_default_route failed");

        // デフォルトルートが追加されていることを確認する
        let routes = nl.get_ipv4_default_routes().await
            .expect("get_ipv4_default_routes failed");
        assert!(
            routes.contains(&lo_index),
            "default route via lo should exist"
        );

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// IPv4 デフォルトルートの置き換えを Network Namespace 内で検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_replace_ipv4_default_route() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|handle| async move {
        let mut nl = RtNetlinkHandle::new(handle);

        let lo_index = nl.get_link_index("lo").await
            .expect("get lo ifindex failed");

        // 最初のデフォルトルートを追加する
        nl.add_ipv4_default_route(lo_index).await
            .expect("first add_ipv4_default_route failed");

        // 2 回目の呼び出しは既存ルートを削除してから再追加する
        nl.add_ipv4_default_route(lo_index).await
            .expect("second add_ipv4_default_route failed");

        // デフォルトルートが 1 件存在することを確認する
        let routes = nl.get_ipv4_default_routes().await
            .expect("get_ipv4_default_routes failed");
        assert_eq!(routes.len(), 1, "should have exactly one default route");
        assert_eq!(routes[0], lo_index);

        Ok(())
    })
    .await
    .expect("netns run failed");
}
