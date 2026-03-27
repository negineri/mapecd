//! nftables ルールセット管理モジュール（Phase 7）
//!
//! CE IPv4-in-IPv6 MAP-E に必要な nftables ルールの生成・適用を担う。
//!
//! - `generate_ruleset`: ポートセット・NAT・MSS クランプ・BR フィルタの
//!   ルール文字列を生成する純粋関数
//! - `CommandExecutor` trait: `nft -f -` へのパイプ実行を抽象化
//! - `NftExecutor`: 本番用実装（`tokio::process::Command`）
//! - `apply_ruleset`: 原子的ルールセット入れ替え（flush → 適用）

pub mod manager;
