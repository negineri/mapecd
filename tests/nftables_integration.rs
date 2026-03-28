#![cfg(target_os = "linux")]

mod common;

use mapecd::nftables::manager::{
    apply_ruleset, delete_tables, generate_ruleset, NftExecutor,
};

/// nftables ルールセットの適用・削除を検証する。
///
/// root 権限が必要（nft コマンドの実行）。
#[tokio::test(flavor = "current_thread")]
async fn test_apply_and_delete_ruleset() {
    let executor = NftExecutor;
    let port_ranges = vec![4101u16..=4356u16, 8197u16..=8452u16];
    let br_address: std::net::Ipv6Addr = "2001:db8:ff::1".parse().unwrap();

    // ルールセットを適用する
    let result = apply_ruleset(&executor, &port_ranges, "lo", br_address).await;
    if let Err(e) = &result {
        // 権限不足の場合はスキップ
        let msg = e.to_string();
        if msg.contains("Operation not permitted") || msg.contains("Permission denied") {
            eprintln!("Skipping test: insufficient privileges for nft ({msg})");
            return;
        }
    }
    result.expect("apply_ruleset failed");

    // ルールセットを削除する
    delete_tables(&executor).await.expect("delete_tables failed");
}

/// nftables ルールセットの構文を検証する（dry-run: `nft -c -f -`）。
#[tokio::test(flavor = "current_thread")]
async fn test_ruleset_syntax_valid() {
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;

    let port_ranges = vec![4101u16..=4356u16, 8197u16..=8452u16];
    let br_address: std::net::Ipv6Addr = "2001:db8:ff::1".parse().unwrap();
    let ruleset = generate_ruleset(&port_ranges, "lo", br_address);

    // nft -c -f - でシンタックスチェックする
    let mut child = match Command::new("nft")
        .args(["-c", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Skipping test: nft command not available ({e})");
            return;
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(ruleset.as_bytes()).await;
    }

    let output = child.wait_with_output().await.expect("wait_with_output failed");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // 権限不足は許容する（-c でも一部のチェックに root が必要）
        if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
            eprintln!("Skipping syntax check: insufficient privileges ({stderr})");
            return;
        }
        panic!("nft syntax check failed: {stderr}");
    }
}

/// ポート範囲が nftables セット要素として正しく生成されることを検証する。
#[tokio::test(flavor = "current_thread")]
async fn test_port_ranges_in_nft_set() {
    let port_ranges = vec![4101u16..=4101u16, 4357u16..=4612u16];
    let br_address: std::net::Ipv6Addr = "2001:db8:ff::1".parse().unwrap();
    let ruleset = generate_ruleset(&port_ranges, "lo", br_address);

    // 単一ポートと範囲の両方が含まれることを確認する
    assert!(
        ruleset.contains("4101"),
        "single port 4101 should appear in ruleset"
    );
    assert!(
        ruleset.contains("4357-4612"),
        "port range 4357-4612 should appear in ruleset"
    );
    assert!(
        ruleset.contains("elements = {"),
        "elements block should be present"
    );
}
