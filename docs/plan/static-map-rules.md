# config.toml への静的 MAP ルール設定の追加

## 経緯

### 問題: DHCPv6 Option 94 が実環境で配信されない可能性

`mapecd` の当初設計では、MAP ルール（IPv6/IPv4 プレフィックス・EA-bits・BR アドレス等）を
DHCPv6 `OPTION_S46_CONT_MAPE`（RFC 7598, Option 94）から動的に取得することを前提としていた。

しかし、フレッツ光 IPoE のパケットキャプチャ解析（`docs/ipoe-connection-analysis.md`）において、
DHCPv6 Reply（フレーム 24）に含まれるオプションを確認したところ、**Option 94 が存在しなかった**。

フレーム 24 に確認されたオプション:
- Option 11 (Authentication)
- Option 17 (Vendor-specific, NTT 固有)
- Option 22 (SIP Server)
- Option 23 (DNS Server)
- Option 24 (Domain Search List)
- Option 25 (IA_PD) ← CE プレフィックス委譲
- Option 31 (SNTP Server)

### OCN バーチャルコネクト (v6プラス) の MAP ルール取得方式

`docs/v6plus-maprule.md` の調査によると、OCN バーチャルコネクト（v6プラス）では
MAP ルールを DHCPv6 Option 94 ではなく、**HTTPS API** から取得している:

```
GET https://rule.map.ocn.ad.jp/?ipv6Prefix=<prefix>&ipv6PrefixLength=<length>&key=<key>
```

この `key` は NTT ドコモと守秘義務契約を結んで払い出される非公開値であり、
`mapecd` が直接取得することは現実的ではない。

### 現状のキャッシュ方式の問題

現状は `map_rules_cache_file`（デフォルト `/run/mapecd/rules.cache`）に JSON 形式で
事前書き込みすることで静的ルールとして機能させられるが、以下の問題がある:

1. `/run/mapecd/` は `tmpfs` のため、**リブート時に消える**
2. JSON フォーマットを手書きするのは煩雑
3. `config.toml` と設定が分散する
4. 「キャッシュ（動的取得の副産物）」と「静的設定（管理者の意図）」が混在する

### 結論

MAP ルールを `config.toml` の `[[map_rules]]` セクションに直接記述できるようにする。
これにより、DHCPv6 Option 94 が配信されない環境でも永続的に動作させられる。

---

## 設計方針

### フォーマット: フラット形式（psid_length 省略可）

v6plus-maprule.md のデータ列:

```
IPv6プレフィックス  IPv6プレフィックス長  IPv4プレフィックス  IPv4プレフィックス長  psid_offset  ea_length  BR_IPv6アドレス
2400:4050:0000::   34                   153.240.0.0       16                  6           22         2001:380:A120::9
```

これを config.toml に転記しやすいよう、フィールド名は上記順序に対応させる:

```toml
[[map_rules]]
ipv6_prefix = "2400:4050::/34"
ipv4_prefix = "153.240.0.0/16"
ea_length   = 22
psid_offset = 6
# psid_length は省略可: ea_length - (32 - ipv4_prefix_len) で自動計算
# 22 - (32 - 16) = 6
br_address  = "2001:380:a120::9"
```

### psid_length の自動計算

`psid_length` は `ea_length` と `ipv4_prefix` の長さから一意に決まる:

```
psid_length = ea_length - (32 - ipv4_prefix_len)
```

OCN バーチャルコネクトのルールでは常に `psid_length = 6` となる（以下確認済み）:

| ea_length | ipv4_prefix_len | psid_length |
|-----------|-----------------|-------------|
| 22        | 16              | 6           |
| 21        | 17              | 6           |
| 20        | 18              | 6           |
| 19        | 19              | 6           |
| 18        | 20              | 6           |
| 17        | 21              | 6           |

ただし自動計算が意図と異なる場合のために、明示指定も可能とする:

```toml
[[map_rules]]
ipv6_prefix  = "2400:4050::/34"
ipv4_prefix  = "153.240.0.0/16"
ea_length    = 22
psid_offset  = 6
psid_length  = 6   # 明示指定（省略可）
br_address   = "2001:380:a120::9"
```

### is_fmr のデフォルト

`is_fmr` フィールドは RFC 7597 の FMR (Forwarding Mapping Rule) フラグに対応する。
静的設定では常に `true` とし、省略可とする。
明示的に `false` にしたい場合のみ記述する。

### プレフィックスのホストビット挙動

`ipv6_prefix` / `ipv4_prefix` は `ipnet` クレートの `Ipv6Net` / `Ipv4Net` で受け取る。
`ipnet` は CIDR を自動正規化する（例: `192.168.1.5/24` → `192.168.1.0/24`）。
このためホストビット付きの誤記はエラーにならず無言で正規化される。

誤記を検出する用途では追加チェックが必要だが、本実装では **正規化を許容する**。
管理者が転記する値（v6plus-maprule.md のデータ列）はホストビットが立たない形式のため
実運用上の問題は生じない。

### 重複ルールの扱い

同一 IPv6 プレフィックスが `[[map_rules]]` に複数定義された場合、
`Config::validate()` ではエラーとせず **定義順先勝ち**（最初にマッチしたルールを使用）とする。
これは `map::calc` における `find()` の挙動と一致する。

### DHCPv6 Option 94 との優先順位

`[[map_rules]]` が設定されている場合は **静的設定を優先**し、DHCPv6 からの MAP ルールを無視する。
これにより、静的設定の意図が DHCPv6 の動的取得によって上書きされることを防ぐ。

**キャッシュファイルの動作:**
静的設定が有効な場合、`map_rules_cache_file` は起動時に参照されず、
`handle_both` でも更新されない。既存のキャッシュファイルが残っていても無視される。

**`IaPdReceived` / `LeaseEvent` 経由の挙動:**
`handle_ia_pd` は `pending_map_rules` を変更しない。
起動時に静的設定が `pending_map_rules` へ設定済みであれば、IA_PD 受信時に
`apply_if_ready` が呼ばれ、両方揃った時点で正常に適用される。

| 条件 | 動作 |
|------|------|
| `[[map_rules]]` あり | 静的設定を使用。DHCPv6 Option 94 は無視 |
| `[[map_rules]]` なし、Option 94 あり | DHCPv6 から動的取得（従来通り） |
| `[[map_rules]]` なし、Option 94 なし、キャッシュあり | キャッシュファイルから読み込み（従来通り） |
| `[[map_rules]]` なし、Option 94 なし、キャッシュなし | `pending_map_rules = None` のまま待機。IA_PD を受信しても MAP ルールが揃わず設定非適用 |

---

## 実装変更点

### 1. config.rs: MapRuleConfig 構造体の追加

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct MapRuleConfig {
    pub ipv6_prefix: Ipv6Net,
    pub ipv4_prefix: Ipv4Net,
    pub ea_length: u8,
    pub psid_offset: u8,
    pub psid_length: Option<u8>,   // None の場合は自動計算
    pub br_address: Ipv6Addr,
    #[serde(default = "default_true")]
    pub is_fmr: bool,
}

impl MapRuleConfig {
    /// psid_length を解決する。
    /// 明示されていない場合は ea_length と ipv4_prefix から計算する。
    ///
    /// `ea_length == 32 - ipv4_prefix_len` の場合は `psid_length = 0` となる
    /// （PSID ビット幅ゼロ = 1 対 1 マッピング）。これは合法な値であり、
    /// `PortParams::default()` と同様に扱われる。
    pub fn resolve_psid_length(&self) -> Result<u8, MapEError> {
        if let Some(k) = self.psid_length {
            return Ok(k);
        }
        let ipv4_suffix_bits = 32u8 - self.ipv4_prefix.prefix_len();
        let k = self.ea_length.checked_sub(ipv4_suffix_bits)
            .ok_or_else(|| MapEError::InvalidConfig(
                format!("ea_length({}) < ipv4 suffix bits({})", self.ea_length, ipv4_suffix_bits)
            ))?;
        Ok(k)
    }

    /// 値の整合性を検証する。
    ///
    /// 以下を検証する:
    /// - `ea_length >= 32 - ipv4_prefix_len`
    ///   （`resolve_psid_length()` 内の `checked_sub` によるアンダーフロー検出で担保）
    /// - `ipv6_prefix.prefix_len() + ea_length <= 128`
    ///   （`build_ce_ipv6` で `!0u128 << (128 - r_plus_ea)` を計算するため超過すると panic）
    /// - `psid_offset + psid_length <= 16`
    ///   （`port_set::calc_port_ranges` が `1u32 << (16 - a - k)` を計算するため、
    ///   この制約を超えると panic または不正値になる）
    pub fn validate(&self) -> Result<(), MapEError> {
        let psid_length = self.resolve_psid_length()?;

        // ipv6_prefix.prefix_len() + ea_length <= 128
        // build_ce_ipv6 で `!0u128 << (128 - r_plus_ea)` を計算するため超過すると panic。
        let r = self.ipv6_prefix.prefix_len() as u32;
        let ea = self.ea_length as u32;
        if r + ea > 128 {
            return Err(MapEError::InvalidConfig(format!(
                "ipv6_prefix_len({r}) + ea_length({ea}) must be <= 128"
            )));
        }

        // psid_offset + psid_length <= 16
        // calc_port_ranges で `1u32 << (16 - a - k)` を計算するため超過すると panic。
        let a = self.psid_offset as u32;
        let k = psid_length as u32;
        if a + k > 16 {
            return Err(MapEError::InvalidConfig(format!(
                "psid_offset({a}) + psid_length({k}) must be <= 16"
            )));
        }

        Ok(())
    }

    /// MapRule に変換する。
    pub fn into_map_rule(self) -> Result<MapRule, MapEError> {
        self.validate()?;
        let psid_length = self.resolve_psid_length()?;
        Ok(MapRule {
            ipv6_prefix: self.ipv6_prefix,
            ipv4_prefix: self.ipv4_prefix,
            ea_length: self.ea_length,
            is_fmr: self.is_fmr,
            br_address: self.br_address,
            port_params: PortParams {
                psid_offset: self.psid_offset,
                psid_length,
            },
        })
    }
}

fn default_true() -> bool { true }
```

### 2. Config 構造体への map_rules フィールド追加

```rust
pub struct Config {
    pub upstream_interface: String,
    pub tunnel_interface: String,
    // ... 既存フィールド ...
    #[serde(default)]
    pub map_rules: Vec<MapRuleConfig>,   // 追加
}
```

既存の `Config::validate()` に各ルールの検証を追加する:

```rust
fn validate(&self) -> Result<(), MapEError> {
    validate_interface_name(&self.upstream_interface)?;
    validate_interface_name(&self.tunnel_interface)?;
    // ... 既存チェック ...

    // 静的 MAP ルールの検証（Config::load() 時点でフェイルファスト）
    for (i, rule) in self.map_rules.iter().enumerate() {
        rule.validate().map_err(|e| MapEError::InvalidConfig(
            format!("map_rules[{i}]: {e}")
        ))?;
    }

    Ok(())
}
```

これにより `Config::load()` 時点で不正なルールを検出でき、runner.rs まで遅延しない。

### 3. runner.rs: 静的設定の優先適用

`Config::validate()` で整合性確認済みだが、`into_map_rule()` は内部で `validate()` を再実行する
ため Err 分岐は理論上到達しない。ただしプログラミングミス等への防御として Err 分岐を残す:

```rust
// (3) MAP Rule: 静的設定 > キャッシュファイルの順で読み込む
if !config.map_rules.is_empty() {
    // 静的設定が指定されている場合はそちらを優先
    // into_map_rule() は内部で validate() を再実行する。Config::load() 時点で検証済みのため
    // 実際には Err にならないが、念のためエラーハンドリングを残す。
    let rules: Result<Vec<MapRule>, _> = config.map_rules.iter()
        .cloned()
        .map(|r| r.into_map_rule())
        .collect();
    match rules {
        Ok(r) => {
            tracing::info!(count = r.len(), "MAP rules loaded from config (static)");
            state.pending_map_rules = Some(r);
        }
        Err(e) => {
            // Config::load() で検証済みのため通常到達しない
            tracing::error!("static MAP rules invalid (BUG): {e}");
            return Err(e.into());
        }
    }
} else if let Some(rules) = load_rules_cache(&config.map_rules_cache_file) {
    // 静的設定なし: キャッシュから読み込む（従来の動作）
    tracing::info!(path = %config.map_rules_cache_file.display(), rules = rules.len(), "MAP rules loaded from cache");
    state.pending_map_rules = Some(rules);
}
```

DHCPv6 `Both` イベント受信時も静的設定優先のガードを追加:

```rust
async fn handle_both(...) {
    // 静的設定がある場合は DHCPv6 からの MAP ルールを無視する。
    // IA_PD（pending_ia_pd）は静的設定の有無にかかわらず常に更新する。
    if config.map_rules.is_empty() {
        // キャッシュ保存・state 更新（既存処理）
        save_rules_cache(...);
        state.pending_map_rules = Some(rules);
    } else {
        tracing::debug!("DHCPv6 MAP rules ignored (static config takes precedence)");
    }
    // IA_PD は常に更新（MAP ルールのソースに依存しない）
    state.pending_ia_pd = Some(ia_pd);
    apply_if_ready(...).await;
}
```

---

## config.toml 設定例（v6plus / OCN バーチャルコネクト）

### 最小構成（MAP ルール 1 件のみ）

```toml
upstream_interface = "eth0"
tunnel_interface   = "mape0"

[[map_rules]]
ipv6_prefix = "2400:4050::/34"
ipv4_prefix = "153.240.0.0/16"
ea_length   = 22
psid_offset = 6
br_address  = "2001:380:a120::9"
```

### 完全なデータベース（v6plus-maprule.md より）

数十〜数百件のルールを列挙することを想定。各ルールは同一形式:

```toml
upstream_interface = "eth0"
tunnel_interface   = "mape0"

# OCN バーチャルコネクト MAP ルール (2026年1月時点)
# IPv6プレフィックス  IPv6plen  IPv4プレフィックス  IPv4plen  a  ea  BR
# 2400:4050:0000::    34       153.240.0.0        16        6  22 2001:380:A120::9

[[map_rules]]
ipv6_prefix = "2400:4050::/34"
ipv4_prefix = "153.240.0.0/16"
ea_length   = 22
psid_offset = 6
br_address  = "2001:380:a120::9"

[[map_rules]]
ipv6_prefix = "2400:4050:4000::/35"
ipv4_prefix = "153.241.0.0/17"
ea_length   = 21
psid_offset = 6
br_address  = "2001:380:a120::9"

# ... (以下同形式で続く)
```

---

## config-format.md への反映

`docs/config-format.md` の `[map_rule]` セクション（単数形・コメントアウト済み）を
`[[map_rules]]`（複数形・有効な記述）に更新し、上記フォーマットに合わせる。

### 変更点サマリー

| 変更前 | 変更後 | 理由 |
|--------|--------|------|
| `[map_rule]` (単数) | `[[map_rules]]` (配列) | 複数ルール対応 |
| コメントアウト | 有効なサンプル | 主要な設定経路として位置づけ |
| `port_params` ネスト | `psid_offset` / `psid_length` フラット | v6plus-maprule.md 形式に合わせ転記しやすく |
| `psid_length` 必須 | `psid_length` 省略可 | 自動計算で利便性向上 |
| `wan_interface` (誤記) | `upstream_interface` (修正済み) | 実装上のフィールド名に統一 |
| `psid_offset` v6プラスは `4`（誤記）| `psid_offset` v6プラスは `6`（修正済み）| v6plus-maprule.md の実データに基づく |
| `psid_length` v6プラスは `8`（誤記）| `psid_length` v6プラスは `6`（修正済み）| 同上 |

---

## テスト方針

### 追加するユニットテスト

1. `MapRuleConfig::resolve_psid_length`: psid_length 省略時の自動計算
2. `MapRuleConfig::resolve_psid_length`: `psid_length = 0` となるケース（ea_length == 32 - ipv4_prefix_len）
3. `MapRuleConfig::resolve_psid_length`: `Some(k)` 明示時は計算を行わないこと
4. `MapRuleConfig::validate`: `psid_offset + psid_length > 16` のエラーケース
5. `MapRuleConfig::validate`: `ipv6_prefix_len + ea_length > 128` のエラーケース
6. `MapRuleConfig::validate`: ea_length < ipv4_suffix_bits のエラーケース
7. `MapRuleConfig::into_map_rule`: 全フィールドの変換（正常ケース）
8. `Config::load` (TOML parse): `[[map_rules]]` の正常ケース
9. `Config::load` (TOML parse): `[[map_rules]]` の異常ケース（必須フィールド欠落・不正プレフィックス形式・validate エラー等）

### 既存テストへの影響

`config.rs` の既存テストは `map_rules` が `Vec::new()` のケース相当のため影響なし。
`runner.rs` の `test_cache_roundtrip` 等も静的設定なし時の動作テストのため影響なし。

### runner.rs への追加テスト

10. 静的設定あり時にキャッシュファイルを無視すること（`pending_map_rules` が静的ルールで設定されること）
11. 静的設定あり時に `handle_both` が DHCPv6 ルールで `pending_map_rules` を上書きしないこと
12. 静的設定あり時に `handle_both` が IA_PD（`pending_ia_pd`）は更新すること

**テスト 10〜12 の実装方針:**

`handle_both` は現状 `#[cfg(target_os = "linux")]` の非公開関数であり、そのままではユニットテスト不可。
以下のいずれかのアプローチを取る:

- **推奨**: `handle_both` の MAP ルール更新ロジックを `apply_map_rules_from_dhcp(state, config, rules)` のような
  `pub(crate)` 関数に抽出し、その関数をユニットテストする。
- 代替: `handle_both` 自体を `pub(crate)` に変更し、テスト側でモックを渡す（`NetlinkHandle` / `CommandExecutor` が
  trait オブジェクトのため、テスト用モック実装は既存の `#[cfg(test)]` モックを流用できる）。
