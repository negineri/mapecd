#![cfg(target_os = "linux")]

mod common;

use common::netns::TestNetNs;

/// Network Namespace 内で /proc/sys/net/ipv4/ip_forward を読み書きできることを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_sysctl_ip_forward_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|_handle| async move {
        let path = "/proc/sys/net/ipv4/ip_forward";

        // 現在の値を読む
        let original = std::fs::read_to_string(path)
            .map(|s| s.trim_end().to_string())
            .expect("read ip_forward failed");

        // 値を "1" に設定する
        std::fs::write(path, "1").expect("write ip_forward=1 failed");
        let val = std::fs::read_to_string(path)
            .map(|s| s.trim_end().to_string())
            .expect("read ip_forward after write failed");
        assert_eq!(val, "1", "ip_forward should be 1 after write");

        // 元の値に戻す
        std::fs::write(path, &original).expect("restore ip_forward failed");

        Ok(())
    })
    .await
    .expect("netns run failed");
}

/// Network Namespace 内で /proc/sys/net/ipv6/conf/all/forwarding を
/// 読み書きできることを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_sysctl_ipv6_forward_in_netns() {
    let ns = TestNetNs::create().expect("TestNetNs::create failed");
    ns.bring_up_lo().await.expect("bring_up_lo failed");

    ns.run(|_handle| async move {
        let path = "/proc/sys/net/ipv6/conf/all/forwarding";

        // 現在の値を読む
        let original = std::fs::read_to_string(path)
            .map(|s| s.trim_end().to_string())
            .expect("read ipv6 forwarding failed");

        // 値を "1" に設定する
        std::fs::write(path, "1").expect("write ipv6 forwarding=1 failed");
        let val = std::fs::read_to_string(path)
            .map(|s| s.trim_end().to_string())
            .expect("read ipv6 forwarding after write failed");
        assert_eq!(val, "1", "ipv6 forwarding should be 1 after write");

        // 元の値に戻す
        std::fs::write(path, &original).expect("restore ipv6 forwarding failed");

        Ok(())
    })
    .await
    .expect("netns run failed");
}
