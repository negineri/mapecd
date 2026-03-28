#![cfg(target_os = "linux")]

/// veth ペアを作成し、両端の ifindex を返す。
#[allow(dead_code)]
pub async fn create_veth_pair(
    _handle: &rtnetlink::Handle,
    _name_a: &str,
    _name_b: &str,
) -> anyhow::Result<(u32, u32)> {
    // Phase 7 実装予定（スタブ）
    unimplemented!("create_veth_pair: Phase 7 で実装予定")
}

/// 指定 ifindex のリンクを UP 状態にする。
#[allow(dead_code)]
pub async fn set_link_up(
    _handle: &rtnetlink::Handle,
    _ifindex: u32,
) -> anyhow::Result<()> {
    // Phase 7 実装予定（スタブ）
    unimplemented!("set_link_up: Phase 7 で実装予定")
}

/// 指定 ifindex に IPv6 リンクローカルアドレスを付与する。
#[allow(dead_code)]
pub async fn add_ipv6_linklocal(
    _handle: &rtnetlink::Handle,
    _ifindex: u32,
) -> anyhow::Result<()> {
    // Phase 7 実装予定（スタブ）
    unimplemented!("add_ipv6_linklocal: Phase 7 で実装予定")
}
