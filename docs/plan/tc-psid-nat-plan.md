# tc pedit を用いた PSID 準拠ポート NAT 実装計画

## 背景・問題

MAP-E CE では、送信パケットの送信元ポートを **PSID に対応した非連続ポートレンジ** 内に制限する必要がある。

現行の nftables `masquerade to :@port_ranges` 構文は **nftables の文法として存在しない**（`unknown raw payload base` エラー）。
複数の `masquerade to :range` ルールを並べる回避策では、nftables が最初のルールのみを適用するため PSID 非準拠となる。

## 解決アプローチ

参考: [tc を用いた MAP-E ポート変換](https://turgenev.hatenablog.com/entry/2024/04/23/031222)

```
送信パケット
  │
  ▼
[nftables SNAT]  ─→  中間レンジ（PSID ビット = 0、連続ポート）
  │
  ▼
[tc pedit egress]  ─→  PSID ビットを OR で埋め込む
  │
  ▼
最終ポート（PSID 準拠、非連続ポートレンジ）
```

### ポート構造

MAP-E ポートのビットレイアウト（RFC 7597, psid_offset=a, psid_length=k, psid=q）:

```
bit 15                               bit 0
┌──────────┬─────────────┬──────────────────────┐
│ a bits   │ k bits      │ (16-a-k) bits        │
│ (高位)   │ PSID = q    │ (低位)               │
│ 1 以上   │ 固定        │ 任意                 │
└──────────┴─────────────┴──────────────────────┘
```

### 中間レンジの定義

PSID ビット位置をゼロにした連続ポート群を「中間レンジ」として使う。

- 最小ポート: `1 << (16 - a)` （高位 a ビットが最小値 1）
- 有効ポート数: `(2^a - 1) * 2^(16-a-k)`
- 中間レンジ: `[1 << (16-a), (1 << (16-a)) + (2^a - 1) * 2^(16-a-k) - 1]`

ただし PSID ビット = 0 の連続範囲に限らず、SNAT のポート割り当てエンジンに任せる場合は
単純に `[staging_base, staging_base + port_count - 1]` の連続レンジを使い、
tc pedit 側で PSID ビットを OR するだけで正しいポートになる。

### tc pedit 変換

1 回の pedit 操作で PSID ビットを埋め込む:

```
and_mask = ~(((1 << k) - 1) << (16 - a - k))  // PSID ビットをクリア
or_value  = psid << (16 - a - k)                // PSID をセット
final_port = (staging_port & and_mask) | or_value
```

TCP・UDP それぞれに別ルールが必要（チェックサム再計算を含む）。

---

## モジュール構成（追加分）

```text
src/
├── tc/
│   ├── mod.rs          # pub use
│   └── manager.rs      # TcManager: ルール生成・apply / cleanup
│
└── daemon/
    └── lifecycle.rs    # tc 操作を apply/cleanup/update に統合
```

---

## 実装ステップ

### Step 1: 中間レンジ計算関数の追加

**対象ファイル**: `src/map/port_set.rs`

`calc_staging_range(psid_offset: u8, psid_length: u8) -> (u16, u16)`

- 戻り値: `(staging_min, staging_max)`
- `staging_min = 1 << (16 - psid_offset)`
- `port_count = (2u32.pow(psid_offset as u32) - 1) * 2u32.pow((16 - psid_offset - psid_length) as u32)`
- `staging_max = staging_min + port_count as u16 - 1`

**テスト**:
- a=4, k=8 (v6plus): `staging_min=4096, port_count=3840, staging_max=7935`
- a=6, k=6 (OCN): 対応する値
- a=0, k=0 (PSID なし): `staging_min=1, staging_max=65535`

---

### Step 2: tc pedit 用ビットマスク計算

**対象ファイル**: `src/tc/manager.rs`（新規）

```rust
/// 中間レンジポートを PSID ポートに変換するビット操作パラメータを計算する。
///
/// 返り値: (and_mask, or_value)
/// - and_mask: PSID ビットをクリアするための 16 ビットマスク
/// - or_value: PSID をセットするための 16 ビット値
pub fn calc_pedit_params(psid_offset: u8, psid_length: u8, psid: u16) -> (u16, u16) {
    let shift = 16 - psid_offset - psid_length;
    let psid_mask = ((1u16 << psid_length) - 1) << shift;
    let and_mask = !psid_mask;
    let or_value = psid << shift;
    (and_mask, or_value)
}
```

**テスト**:
- a=4, k=8, psid=0x3A: `and_mask=0xF00F, or_value=0x03A0`
- a=4, k=8, psid=0: `and_mask=0xF00F, or_value=0x0000`
- a=0, k=0, psid=0: `and_mask=0xFFFF, or_value=0x0000`（変換なし）

---

### Step 3: nftables SNAT ルールの変更

**対象ファイル**: `src/nftables/manager.rs`

`generate_ruleset` の `chain postrouting` を `masquerade` から `snat` に変更:

```nftables
chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "{tunnel_interface}" meta l4proto { tcp, udp }
        snat to :{staging_min}-{staging_max}
}
```

`generate_ruleset` のシグネチャ変更:

```rust
pub fn generate_ruleset(
    port_ranges: &[RangeInclusive<u16>],
    staging_range: (u16, u16),        // 追加
    tunnel_interface: &str,
    br_address: Ipv6Addr,
) -> String
```

**テスト**: 既存テストを `staging_range` 引数付きに更新

---

### Step 4: `TcHandle` トレイトと `TcManager` 実装

**対象ファイル**: `src/tc/manager.rs`

```rust
pub trait TcHandle: Send {
    async fn apply_psid_pedit(
        &mut self,
        interface: &str,
        psid_offset: u8,
        psid_length: u8,
        psid: u16,
        staging_min: u16,
        staging_max: u16,
    ) -> Result<(), MapEError>;

    async fn delete_psid_pedit(&mut self, interface: &str) -> Result<(), MapEError>;
}

pub struct TcManager;
```

`TcManager::apply_psid_pedit` が発行する tc コマンド列:

```bash
# 1. egress qdisc を設定
tc qdisc replace dev {iface} root handle 1: htb

# 2. TCP 送信元ポート変換
tc filter add dev {iface} parent 1: protocol ip u32 \
    match ip protocol 6 0xff \
    match ip sport {staging_min} 0xffff \  # TODO: 範囲マッチ
    action pedit ex \
        munge tcp sport and {and_mask_be} or {or_value_be} retain \
    pipe \
    action csum tcp

# 3. UDP 送信元ポート変換
tc filter add dev {iface} parent 1: protocol ip u32 \
    match ip protocol 17 0xff \
    action pedit ex \
        munge udp sport and {and_mask_be} or {or_value_be} retain \
    pipe \
    action csum udp
```

> **注意**: tc pedit でポート範囲マッチを行うには u32 セレクタでは困難なため、
> 代替として `flower` フィルタまたは eBPF の利用も検討する（Step 6 参照）。

**テスト**: `MockTcHandle` を用いたコマンド列検証

---

### Step 5: `lifecycle.rs` への統合

**対象ファイル**: `src/daemon/lifecycle.rs`

`apply` に tc 適用ステップを追加:

```rust
// Step 5: nftables SNAT（中間レンジへ）
let staging_range = calc_staging_range(&params.rule.port_params);
apply_ruleset(executor, &port_ranges, staging_range, ...).await?;

// Step 6: tc pedit（PSID ビット埋め込み）
tc.apply_psid_pedit(
    &config.tunnel_interface,
    params.rule.port_params.psid_offset,
    params.rule.port_params.psid_length,
    params.psid,
    staging_range.0,
    staging_range.1,
).await?;
```

`cleanup` で `tc.delete_psid_pedit` を呼ぶ。

`DaemonState` に `staging_range: Option<(u16, u16)>` を追加し、cleanup 時の情報保持に使う。

**統合テスト**: `full_lifecycle_integration.rs` に tc 操作込みの lifecycle テスト追加（tc が使えない環境ではスキップ）

---

### Step 6: ポート範囲マッチの精緻化（オプション）

u32 セレクタによるポート範囲マッチが困難な場合のフォールバック:

**Option A: eBPF (tc BPF) による実装**
- tc filter に BPF プログラムをアタッチ
- BPF でポート範囲チェックと変換を行う
- パフォーマンス最良だが実装コスト大

**Option B: 送信ポートマッチなしで全パケットに適用**
- staging range 以外のポートがそのまま送出されるリスク
- SNAT が正しく staging range 内に制限されていれば実用上問題なし

**Option C: nftables ingress フック + redirect**
- tc egress の代わりに nftables egress フック（Linux 5.17+）を使う

---

## `DaemonState` への追加フィールド

```rust
pub struct DaemonState {
    // 既存フィールド
    pub tunnel_ifindex: Option<u32>,
    pub original_ip_forward: Option<String>,
    pub original_ipv6_forward: Option<String>,

    // 追加
    pub staging_range: Option<(u16, u16)>,  // tc pedit cleanup 用
}
```

---

## 影響範囲

| ファイル | 変更種別 |
|----------|---------|
| `src/map/port_set.rs` | `calc_staging_range` 関数追加 |
| `src/tc/mod.rs` | 新規 |
| `src/tc/manager.rs` | 新規（`TcHandle` trait + `TcManager` 実装） |
| `src/nftables/manager.rs` | `generate_ruleset` シグネチャ変更、SNAT ルール変更 |
| `src/daemon/state.rs` | `staging_range` フィールド追加 |
| `src/daemon/lifecycle.rs` | tc 操作ステップ追加 |
| `tests/full_lifecycle_integration.rs` | tc 込みテスト追加 |

---

## 前提条件・依存

- `tc` コマンド（`iproute2`）: `tc pedit` + `tc action csum` が必要
- カーネル: `CONFIG_NET_ACT_PEDIT`, `CONFIG_NET_ACT_CSUM` が有効であること
- Linux カーネル: 4.9 以上（pedit ex の `retain` キーワードは 4.9+）
- IPv6 トンネル上の IPv4 パケットに対しても pedit が適用されること（ip6tnl デバイスでの動作確認が必要）

---

## 未解決事項

1. **ip6tnl デバイスでの tc pedit 動作**: ip6tnl egress で tc filter が正しく動作するか要検証
2. **ポート範囲マッチ**: 中間レンジ外のポートを誤って変換しないための正確なマッチ方法
3. **チェックサムオフロード**: NIC のハードウェアオフロードが有効な場合の pedit との干渉
4. **ICMP 等**: TCP/UDP 以外のプロトコルの扱い（通常は PSID 対象外だが確認が必要）
