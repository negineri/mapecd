# CE IPv6 アドレス形式対応 実装計画

## 背景と課題

`build_ce_ipv6`（`src/map/calc.rs`）は RFC 7597 Section 5.2 準拠の形式で CE IPv6 アドレスを構成しているが、v6プラス（OCN）は非 RFC 形式（`rfc=false`）を使用しているとみられる。形式が一致しない場合、MAP-E トンネルは確立できても実際の通信が通らない。

### 形式の違い

IPv4 アドレス `a.b.c.d`、PSID `p`、psid_length `k` の場合：

**RFC 7597 形式**（現行実装）:
```
bits  0- 63: [IPv6 ルールプレフィックス (r bits) | EA-bits | 0-pad]
bits 64- 79: 0x0000
bits 80-111: a.b.c.d  (32ビット連続)
bits 112-127: p << (16-k)
```

**非 RFC 形式**（v6プラス / `docs/v6plus-maprule.js` の `rfc=false`）:
```
bits  0- 63: [IPv6 ルールプレフィックス (r bits) | EA-bits | 0-pad]
bits 64- 79: 0x00 | a    (上位バイト = 0x00、下位バイト = 第1オクテット。hextet[4] = a として 16 ビット整数に代入)
bits 80- 95: (b << 8) | c (第2・3オクテット)
bits 96-111: d << 8      (第4オクテットを上位バイトに)
bits 112-127: p << 8
```

## 方針

### 設定連動方式を採用する

`use_v6plus_static_rules = true` の場合は非 RFC 形式を使う。これにより：

- 設定の二重管理が不要（v6プラスであることは静的ルール有効化で確定済み）
- 実装変更が最小限
- 将来的に DHCPv6 由来ルールでも非 RFC 形式が必要な場合は `CeFormat` を `MapRule` に持たせる拡張が可能

### 設計方針

`CeFormat` enum を `src/map/rule.rs` に追加し、`build_ce_ipv6` および `compute_mape_params` の引数として渡す。`runner.rs` から `config.use_v6plus_static_rules` に基づいて選択する。

> **定義場所について**: `calc.rs` に定義すると `rule.rs` が `calc.rs` を import する逆方向依存が生じる（現状は `calc.rs` → `rule.rs`）。`CeFormat` はデータ構造として `rule.rs` に置くことで依存方向を維持する。

`MapRule` フィールドには持たせない（ルールはプレフィックス・ポートパラメータのみを表現し、CE 形式はプロバイダ固有の計算方法であるため）。

## 実装スコープ

### 1) `CeFormat` enum の追加（`src/map/rule.rs`）

```rust
/// CE IPv6 アドレスの構成形式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeFormat {
    /// RFC 7597 Section 5.2 準拠。
    /// bits 80-111: IPv4 アドレス（32ビット連続）
    /// bits 112-127: PSID << (16-k)
    Rfc7597,
    /// v6プラス（OCN）非 RFC 形式（docs/v6plus-maprule.js の rfc=false 相当）。
    /// bits 64-79: 0x00 | 第1オクテット（上位バイト=0x00、下位バイトに第1オクテット）
    /// bits 80-95: (第2オクテット << 8) | 第3オクテット
    /// bits 96-111: 第4オクテット << 8
    /// bits 112-127: PSID << 8
    V6Plus,
}
```

### 2) `build_ce_ipv6` の拡張（`src/map/calc.rs`）

```rust
pub fn build_ce_ipv6(
    ce_prefix: Ipv6Net,
    rule: &MapRule,
    ea_bits: u64,
    format: CeFormat,
) -> Ipv6Addr
```

内部で `format` に応じてビット配置を分岐する。既存の RFC 7597 ロジックは `Rfc7597` ブランチとして維持し、`V6Plus` ブランチを追加する。

`V6Plus` ブランチの先頭に以下のガードを置く：
- `debug_assert!(r_plus_ea <= 64)` — `r_plus_ea > 64` の場合、CE プレフィックスのマスク保持範囲がビット 64-79 の V6Plus 用領域と重複し、OR によるオクテット書き込みが正しく行われない。v6plus では r=32, ea=16（r+ea=48）が一般的であり実用上は問題ないが、異常なルールでの無音バグを防ぐために assert を入れる。
- `debug_assert!(rule.port_params.psid_length == 8)` — V6Plus は k=8 固定を前提とする。k≠8 の場合、PSID フィールドが RFC 形式（`p << (16-k)`）と実質的に同じになる保証がなくなり、誤った CE アドレスが生成される。

### 3) `compute_mape_params` の拡張（`src/map/calc.rs`）

```rust
pub fn compute_mape_params(
    ce_prefix: Ipv6Net,
    rule: &MapRule,
    format: CeFormat,
) -> Result<MapeParams, MapEError>
```

`build_ce_ipv6` に `format` を伝播する。また、`MapeParams` 構築時に `ce_format: format` フィールドを設定する。

```rust
Ok(MapeParams {
    ce_ipv6,
    ipv4,
    psid,
    port_ranges,
    br_address: rule.br_address,
    rule: rule.clone(),
    ce_format: format,
})
```

### 4) `MapeParams` へのフィールド追加（`src/map/rule.rs`）

```rust
pub struct MapeParams {
    pub ce_ipv6: Ipv6Addr,
    pub ipv4: Ipv4Addr,
    pub psid: u16,
    pub port_ranges: Vec<RangeInclusive<u16>>,
    pub br_address: Ipv6Addr,
    pub rule: MapRule,
    /// CE IPv6 アドレスの構成に使用した形式。
    pub ce_format: CeFormat,
}
```

`has_changed` の比較対象には含めない（形式変更は設定変更を伴い、デーモン再起動が前提）。

### 5) `DaemonState::try_compute` の変更（`src/daemon/state.rs`）

`CeFormat` を引数として受け取り、`compute_mape_params` に渡す。

```rust
pub fn try_compute(&mut self, format: CeFormat) -> Result<bool, MapEError>
```

### 6) 呼び出し元の変更（`src/daemon/runner.rs`）

`apply_if_ready` で `config.use_v6plus_static_rules` から `CeFormat` を選択して `try_compute` に渡す。

```rust
let format = if config.use_v6plus_static_rules {
    CeFormat::V6Plus
} else {
    CeFormat::Rfc7597
};
state.try_compute(format)
```

起動時ログに使用形式を明記する（既存の静的ルール有効化ログに追記）。

### 7) `MapeParams` ドキュメントコメントの更新（`src/map/rule.rs`）

現在 "RFC 7597 Section 5.2 に従い導出" と記載されているコメントを形式依存の表現に修正する。

## テスト計画

### 単体テスト（`src/map/calc.rs`）

- `build_ce_ipv6` の `Rfc7597` ブランチが既存の期待値と一致すること（回帰）
- `build_ce_ipv6` の `V6Plus` ブランチが非 RFC 形式の期待値と一致すること
  - 期待値: `docs/v6plus-maprule.js` の計算ロジック（`rfc=false` ブランチ）を手動実行して算出
  - 例: Rule=`2001:db8::/32`, IPv4ルールプレフィックス=`192.0.2.0/24`, CE prefix=`2001:db8:6405::/48`, PSID=5, k=8 の場合
    - EA-bits = `0x6405`（bits 32-47）→ IPv4サフィックス=`0x64`=100, PSID=5 → 導出 IPv4 アドレス = **`192.0.2.100`**
    - bits 64-79: `0x00c0`（octet[0]=192）
    - bits 80-95: `0x0002`（(octet[1]<<8)|octet[2] = (0<<8)|2）
    - bits 96-111: `0x6400`（octet[3]<<8 = 100<<8）
    - bits 112-127: `0x0500`（PSID<<8 = 5<<8）
    - 完全な CE IPv6 アドレス（ゴールデン値）: `2001:db8:6405:0:c0:2:6400:500`
  - **注意**: v6plus は k=8 固定のため、PSID フィールド（bits 112-127）は RFC 形式の `p << (16-k)` と V6Plus 形式の `p << 8` が k=8 で一致する。両形式の差異は bits 64-111 の IPv4 エンコード部分にあることをテストコメントに記載すること
  - **命名注意**: `calc.rs` には既存テスト `test_compute_mape_params_v6plus`（v6プラス向けルールデータを RFC 形式でテスト）がある。新規追加する V6Plus フォーマットのテストは `test_build_ce_ipv6_v6plus_format` など明確に区別できる名前を使うこと
- `compute_mape_params` に両形式を渡した場合に `MapeParams.ce_ipv6` が異なること（差異は bits 64-111 の IPv4 部分）
- 既存テスト `test_compute_mape_params_v6plus` に `ce_ipv6` の期待値アサーション（RFC 形式: `2001:db8:6405::c000:264:500`）を追加する（タスク6で対応）。V6Plus 形式のゴールデン値（`2001:db8:6405:0:c0:2:6400:500`）との対比で回帰が明確になる。

### 回帰テスト

- `use_v6plus_static_rules = false` 時に RFC 7597 形式が使われること
- `use_v6plus_static_rules = true` 時に V6Plus 形式が使われること
- これらは `src/daemon/state.rs` の `test_try_compute_success` に `format` 引数を変えた2パターン（`CeFormat::Rfc7597` / `CeFormat::V6Plus`）を追加し、`params.ce_ipv6` の値で形式が正しく切り替わることを検証する

## 実装タスク（順序付き）

0. `try_compute`・`compute_mape_params` の全呼び出し箇所を確認する（現状: `state.rs`・`runner.rs` のみ。`cli.rs` 等に追加呼び出しがないことを検索して確認）
1. `CeFormat` enum を `src/map/rule.rs` に追加
2. `build_ce_ipv6` に `format: CeFormat` 引数を追加し、`V6Plus` ブランチを実装
3. `MapeParams` に `ce_format: CeFormat` フィールドを追加
4. `compute_mape_params` に `format: CeFormat` 引数を追加し伝播（`build_ce_ipv6` への伝播と `MapeParams { ce_format: format, ... }` の設定を含む）
5. `DaemonState::try_compute` に `format: CeFormat` 引数を追加
6. `src/map/calc.rs` の既存テスト3件（`test_build_ce_ipv6_rfc7597`・`test_build_ce_ipv6_psid0`・`test_compute_mape_params_v6plus`）に `format: CeFormat::Rfc7597` 引数を追加
7. `src/daemon/state.rs` の既存テスト4件（`test_try_compute_*`）に `format: CeFormat::Rfc7597` 引数を追加し、`test_try_compute_success` には `params.ce_format == CeFormat::Rfc7597` のアサーションも追加する
8. `src/daemon/lifecycle.rs` の `make_params()` テストヘルパーに `ce_format: CeFormat::Rfc7597` フィールドを追加し、`#[cfg(test)]` スコープに `use crate::map::rule::CeFormat;` を追加
9. `runner.rs` の `apply_if_ready` で `config.use_v6plus_static_rules` から `CeFormat` を選択
10. 起動時ログに CE 形式を明記
11. 単体テスト・回帰テストを追加
12. `MapeParams` のドキュメントコメントを更新

## 注意点

- `CeFormat` を `src/map/rule.rs` の `MapRule` に持たせないこと（ルールはプレフィックス情報のみを表現する設計を維持する）
- `has_changed`（`src/daemon/lifecycle.rs`）の比較対象に `ce_format` を含めないこと（形式変更はデーモン再起動を前提とする）
- `CeFormat` は `rule.rs` に定義すること（`calc.rs` に定義すると `rule.rs` → `calc.rs` の逆方向依存が生じ、現状の依存方向が崩れる）
- `CeFormat` を使う各ファイル（`calc.rs`・`state.rs`・`runner.rs`）に `use crate::map::rule::CeFormat;` の追加が必要
- `src/daemon/state.rs` の既存テスト4件と `src/daemon/lifecycle.rs` の `make_params()` ヘルパーは `MapeParams` / `try_compute` の変更に伴い更新が必要（タスク7・8で対応）
- `src/map/calc.rs` の既存テスト3件（`test_build_ce_ipv6_rfc7597`・`test_build_ce_ipv6_psid0`・`test_compute_mape_params_v6plus`）は `build_ce_ipv6` / `compute_mape_params` のシグネチャ変更に伴い `CeFormat::Rfc7597` 引数の追加が必要（タスク6で対応）
- `build_ce_ipv6` の `V6Plus` ブランチには以下のコメント・ガードを追加すること：
  - `// k=8 固定前提: PSID は常に << 8` のコメントを追記し、想定外の k 値での使用を防ぐこと
  - `debug_assert!(r_plus_ea <= 64)` — V6Plus は bits 64-79 を IPv4 エンコードに使用するため、`r_plus_ea > 64` の場合は CE プレフィックスのマスク保持範囲と衝突する（`r_plus_ea` は `build_ce_ipv6` 内 line 74 で定義済みの変数）
  - `debug_assert!(rule.port_params.psid_length == 8)` — k≠8 では PSID フィールドが RFC 形式と異なる結果になる
- 将来的に DHCPv6 由来ルールで非 RFC 形式が必要になった場合は、`Config` に `ce_format` フィールドを追加するか、BR アドレスによる自動判別を検討する

## 完了条件

- `use_v6plus_static_rules = true` 時に v6プラス非 RFC 形式の CE IPv6 アドレスが生成されること
- `use_v6plus_static_rules = false` 時に既存の RFC 7597 形式が維持されること（回帰なし）
- `docs/v6plus-maprule.js` の計算ロジックと一致するゴールデン期待値がテストに固定されていること
