//! nftables ルールセット生成・適用（ステップ 7-1 〜 7-3）
//!
//! ## ルール骨格
//!
//! ```nftables
//! add table ip mapecd
//! flush table ip mapecd
//! add table ip6 mapecd
//! flush table ip6 mapecd
//!
//! table ip mapecd {
//!     set port_ranges {
//!         type inet_service
//!         flags interval
//!         elements = { <port_range_1>, <port_range_2>, ... }
//!     }
//!     chain postrouting { ... masquerade to :@port_ranges }
//!     chain forward { ... tcp option maxseg size set rt mtu }
//! }
//!
//! table ip6 mapecd {
//!     chain prerouting { ... ip6 nexthdr 4 drop }
//! }
//! ```

use std::{net::Ipv6Addr, ops::RangeInclusive};

use crate::error::MapEError;

// ────────────────────────────────────────────────────────────
// CommandExecutor trait（ステップ 7-2）
// ────────────────────────────────────────────────────────────

/// nftables コマンド実行を抽象化するトレイト。
///
/// 本番実装は `NftExecutor`（`nft -f -` へのパイプ）、
/// テスト用実装は `MockExecutor`。
pub trait CommandExecutor: Send + Sync {
    fn execute(
        &self,
        input: &str,
    ) -> impl std::future::Future<Output = Result<(), MapEError>> + Send;
}

/// 本番用実装: `nft -f -` に nftables ルールセットを標準入力で渡す。
pub struct NftExecutor;

impl CommandExecutor for NftExecutor {
    async fn execute(&self, input: &str) -> Result<(), MapEError> {
        use tokio::{
            io::AsyncWriteExt,
            process::Command,
        };

        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| MapEError::NftError(format!("failed to spawn nft: {e}")))?;

        // 標準入力にルールセットを書き込む
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| MapEError::NftError(format!("write to nft stdin: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| MapEError::NftError(format!("wait for nft: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MapEError::NftError(format!(
                "nft exited with {}: {stderr}",
                output.status
            )));
        }

        Ok(())
    }
}

// ────────────────────────────────────────────────────────────
// generate_ruleset（ステップ 7-1）
// ────────────────────────────────────────────────────────────

/// nftables ルールセット文字列を生成する純粋関数。
///
/// # 引数
/// - `port_ranges`: CE に割り当てられたポート範囲（set port_ranges 定義に使用）
/// - `tunnel_interface`: ip6tnl トンネルインターフェース名
/// - `br_address`: BR の IPv6 アドレス（ingress フィルタで使用）
/// - `staging_range`: eBPF staging range `(min, max)`。masquerade に使用する単一連続レンジ。
///
/// # Panics
/// `port_ranges` が空の場合は呼び出し元で `EmptyPortRanges` ガードを実行すること。
/// この関数内ではパニックしない。
pub fn generate_ruleset(
    port_ranges: &[RangeInclusive<u16>],
    tunnel_interface: &str,
    br_address: Ipv6Addr,
    staging_range: (u16, u16),
) -> String {
    let port_elements = format_port_elements(port_ranges);
    let (staging_min, staging_max) = staging_range;

    format!(
        r#"add table ip mapecd
flush table ip mapecd
add table ip6 mapecd
flush table ip6 mapecd

table ip mapecd {{
    set port_ranges {{
        type inet_service
        flags interval
        elements = {{ {port_elements} }}
    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat;
        oifname "{tunnel_interface}" meta l4proto {{ tcp, udp, icmp }} masquerade to :{staging_min}-{staging_max}
    }}

    chain forward {{
        type filter hook forward priority filter;
        oifname "{tunnel_interface}" tcp flags syn tcp option maxseg size set rt mtu
        iifname "{tunnel_interface}" tcp flags syn tcp option maxseg size set rt mtu
    }}
}}

table ip6 mapecd {{
    chain prerouting {{
        type filter hook prerouting priority filter;
        ip6 saddr != {br_address} ip6 nexthdr 4 drop
    }}
}}
"#
    )
}

/// ポート範囲を nftables の `elements = { ... }` 形式にフォーマットする。
///
/// - 単一ポート: `4101`
/// - 範囲: `4101-4357`
fn format_port_elements(port_ranges: &[RangeInclusive<u16>]) -> String {
    port_ranges
        .iter()
        .map(|r| {
            if r.start() == r.end() {
                r.start().to_string()
            } else {
                format!("{}-{}", r.start(), r.end())
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ────────────────────────────────────────────────────────────
// apply_ruleset（ステップ 7-3）
// ────────────────────────────────────────────────────────────

/// nftables ルールセットを原子的に入れ替える（flush → 適用）。
///
/// ルールセット文字列の先頭に `flush table` が含まれているため、
/// `nft -f -` での一括適用が原子的な入れ替えとなる。
///
/// # エラー
/// - `EmptyPortRanges`: `port_ranges` が空の場合（nft バージョンによりエラーになる）
/// - `NftError`: `nft` コマンドの実行失敗
pub async fn apply_ruleset(
    executor: &impl CommandExecutor,
    port_ranges: &[RangeInclusive<u16>],
    tunnel_interface: &str,
    br_address: Ipv6Addr,
    staging_range: (u16, u16),
) -> Result<(), MapEError> {
    if port_ranges.is_empty() {
        return Err(MapEError::EmptyPortRanges);
    }

    let ruleset = generate_ruleset(port_ranges, tunnel_interface, br_address, staging_range);
    executor.execute(&ruleset).await
}

/// nftables テーブルを削除する（cleanup 時に呼び出す）。
pub async fn delete_tables(executor: &impl CommandExecutor) -> Result<(), MapEError> {
    let rules = "delete table ip mapecd\ndelete table ip6 mapecd\n";
    executor.execute(rules).await
}

// ────────────────────────────────────────────────────────────
// テスト
// ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv6Addr,
        ops::RangeInclusive,
        sync::{Arc, Mutex},
    };

    use super::*;

    // ─── MockExecutor ────────────────────────────────────────

    struct MockExecutor {
        pub calls: Arc<Mutex<Vec<String>>>,
        pub fail: bool,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(vec![])),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: Arc::new(Mutex::new(vec![])),
                fail: true,
            }
        }
    }

    impl CommandExecutor for MockExecutor {
        async fn execute(&self, input: &str) -> Result<(), MapEError> {
            self.calls.lock().unwrap().push(input.to_string());
            if self.fail {
                Err(MapEError::NftError("mock error".to_string()))
            } else {
                Ok(())
            }
        }
    }

    fn br() -> Ipv6Addr {
        "2001:db8::1".parse().unwrap()
    }

    // テスト用デフォルト staging range（a=4, k=8 の場合）
    fn default_staging() -> (u16, u16) {
        (4096, 4335)
    }

    // ─── generate_ruleset スナップショットテスト ─────────────

    #[test]
    fn test_generate_ruleset_contains_flush() {
        let ranges = vec![1u16..=65535u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("flush table ip mapecd"));
        assert!(ruleset.contains("flush table ip6 mapecd"));
    }

    #[test]
    fn test_generate_ruleset_contains_table_names() {
        let ranges = vec![1u16..=65535u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("table ip mapecd"));
        assert!(ruleset.contains("table ip6 mapecd"));
    }

    #[test]
    fn test_generate_ruleset_masquerade_staging_range() {
        // eBPF 版: staging range の単一ルールが生成されること
        let ranges = vec![4176u16..=4191u16, 8272u16..=8287u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), (4096, 4335));

        assert!(
            ruleset.contains(
                "oifname \"ip6tnl0\" meta l4proto { tcp, udp, icmp } masquerade to :4096-4335"
            ),
            "staging range masquerade rule should be present"
        );
        // 旧形式（複数ルール）は存在しないこと
        assert!(
            !ruleset.contains("masquerade to :4176"),
            "old per-range masquerade should not be present"
        );
    }

    #[test]
    fn test_generate_ruleset_mss_clamp_both_directions() {
        let ranges = vec![1u16..=65535u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(
            ruleset.contains("oifname \"ip6tnl0\" tcp flags syn tcp option maxseg size set rt mtu")
        );
        assert!(
            ruleset.contains("iifname \"ip6tnl0\" tcp flags syn tcp option maxseg size set rt mtu")
        );
    }

    #[test]
    fn test_generate_ruleset_br_filter() {
        let br = "2001:db8::ffff".parse::<Ipv6Addr>().unwrap();
        let ranges = vec![1u16..=65535u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br, default_staging());

        assert!(ruleset.contains("ip6 saddr != 2001:db8::ffff ip6 nexthdr 4 drop"));
    }

    #[test]
    fn test_generate_ruleset_single_port_element() {
        let ranges = vec![4101u16..=4101u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("elements = { 4101 }"));
    }

    #[test]
    fn test_generate_ruleset_port_range_element() {
        let ranges = vec![4101u16..=4356u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("elements = { 4101-4356 }"));
    }

    #[test]
    fn test_generate_ruleset_multiple_ranges() {
        let ranges = vec![4101u16..=4101u16, 4357u16..=4357u16, 8197u16..=8452u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("4101, 4357, 8197-8452"));
    }

    #[test]
    fn test_generate_ruleset_full_range() {
        let ranges = vec![1u16..=65535u16];
        let ruleset = generate_ruleset(&ranges, "ip6tnl0", br(), default_staging());

        assert!(ruleset.contains("elements = { 1-65535 }"));
    }

    // ─── apply_ruleset テスト ─────────────────────────────────

    #[tokio::test]
    async fn test_apply_ruleset_empty_port_ranges_returns_error() {
        let executor = MockExecutor::new();
        let result = apply_ruleset(&executor, &[], "ip6tnl0", br(), default_staging()).await;

        assert!(matches!(result, Err(MapEError::EmptyPortRanges)));
        // executor.execute は呼ばれないこと
        assert!(executor.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_apply_ruleset_calls_executor() {
        let executor = MockExecutor::new();
        let ranges = vec![1u16..=65535u16];
        apply_ruleset(&executor, &ranges, "ip6tnl0", br(), default_staging())
            .await
            .unwrap();

        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("flush table ip mapecd"));
    }

    #[tokio::test]
    async fn test_apply_ruleset_propagates_executor_error() {
        let executor = MockExecutor::failing();
        let ranges = vec![1u16..=65535u16];
        let result = apply_ruleset(&executor, &ranges, "ip6tnl0", br(), default_staging()).await;

        assert!(matches!(result, Err(MapEError::NftError(_))));
    }

    #[tokio::test]
    async fn test_delete_tables_calls_executor() {
        let executor = MockExecutor::new();
        delete_tables(&executor).await.unwrap();

        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].contains("delete table ip mapecd"));
        assert!(calls[0].contains("delete table ip6 mapecd"));
    }

    // ─── format_port_elements ユニットテスト ─────────────────

    #[test]
    fn test_format_single_port() {
        let ranges: Vec<RangeInclusive<u16>> = vec![80u16..=80u16];
        assert_eq!(format_port_elements(&ranges), "80");
    }

    #[test]
    fn test_format_range() {
        let ranges: Vec<RangeInclusive<u16>> = vec![1024u16..=2048u16];
        assert_eq!(format_port_elements(&ranges), "1024-2048");
    }

    #[test]
    fn test_format_multiple_mixed() {
        let ranges: Vec<RangeInclusive<u16>> =
            vec![80u16..=80u16, 1024u16..=2048u16, 3000u16..=3000u16];
        assert_eq!(format_port_elements(&ranges), "80, 1024-2048, 3000");
    }

    #[test]
    fn test_format_empty() {
        let ranges: Vec<RangeInclusive<u16>> = vec![];
        assert_eq!(format_port_elements(&ranges), "");
    }
}
