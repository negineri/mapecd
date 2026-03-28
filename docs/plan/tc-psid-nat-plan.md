# tc pedit を用いた PSID 準拠ポート NAT 実装計画

## 背景・問題

MAP-E CE では、送信パケットの送信元ポートを **PSID に対応した非連続ポートレンジ** 内に制限する必要がある。

現行の nftables `masquerade to :@port_ranges` 構文は **nftables の文法として存在しない**（`unknown raw payload base` エラー）。
複数の `masquerade to :range` ルールを並べる回避策では、nftables が最初のルールのみを適用するため PSID 非準拠となる。

> **注意**: 現在の `calc_port_ranges`（`src/map/port_set.rs`）は `Port = R * 2^(a+k) + j * 2^k + PSID`（PSID を低位 k ビットに配置）という RFC 7597 非準拠の式を使っている。本計画では tc pedit と合わせて **RFC 7597 準拠の式**（`Port = R * 2^(16-a) + PSID * 2^(16-a-k) + j`、PSID を中位 k ビットに配置）へ変更することを前提とする。この変更は Step 1 に含める。

## 解決アプローチ

参考: [tc を用いた MAP-E ポート変換](https://turgenev.hatenablog.com/entry/2024/04/23/031222)

> **tc pedit を採用する理由**: tc-bpf（eBPF）は現在の主流で自由度も高いが、BPF プログラムのコンパイルツールチェーン（clang + bpftool 等）が実行環境に不要という実装コストの優位性から、本計画ではまず tc pedit で実装する。  
> ただし、nftables masquerade が単一の連続 port range しか指定できないという制約により、Phase 1 では 1 R-block 分（v6plus で 16 ポート）の利用に限定される（後述）。v6plus 本番利用では Step 6 の複数 R-block 対応が実質必要となる。

```
送信パケット
  │
  ▼
[nftables masquerade]  ─→  中間レンジ（PSID ビット = 0、連続ポート、1 R-block 分）
  │
  ▼
[tc pedit egress]  ─→  PSID ビットを AND+OR で埋め込む
  │
  ▼
最終ポート（PSID 準拠、非連続ポートレンジ）

戻りパケット
  │ (最終ポートが dst_port として到着)
  ▼
[tc pedit ingress]  ─→  PSID ビットをクリア（AND のみ）→ 中間ポートに変換
  │
  ▼
[nftables conntrack]  ─→  中間ポートで接続を逆引き → 内部ホストへ転送
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

PSID ビット位置（中位 k ビット）をゼロにした **1 R-block 分の連続ポート群** を「中間レンジ」として使う。

- 最小ポート（R=1 ブロック先頭）: `1 << (16 - a)`
- 1 R-block のポート数: `2^(16-a-k)`（低位ビットが 0..2^(16-a-k)-1 の範囲）
- 中間レンジ: `[1 << (16-a), (1 << (16-a)) + 2^(16-a-k) - 1]`

> **なぜ 1 R-block に限定するか**: 制約は tc pedit 側ではなく **nftables masquerade 側** にある。  
> tc pedit は R-block ごとにフィルタルールを定義でき、複数 R-block に技術的に対応可能である。  
> しかし nftables masquerade は **単一の連続 port range しか指定できず**、  
> 複数の `masquerade to :range` ルールを並べても最初のルールしか適用されない（当初の問題そのもの）。  
> 複数 R-block の staging range（各 R-block の PSID=0 ポート群、互いに非連続）に  
> 接続を分散させる手段が単純な `masquerade to :range` では実現できないため、  
> Phase 1 では 1 R-block（= 1 staging range）に限定する。  
>
> なお、各 R-block の staging range（PSID ビット = 0）は単体では連続しており、AND+OR 変換は  
> 正しく 1 対 1 写像として機能する（PSID ビット位置がすでに 0 のため AND は無変更、OR で PSID を書き込むだけ）。
>
> 1 R-block あたりのポート数は `2^(16-a-k)`（例: a=4, k=8 で **16 ポート**）。  
> v6plus の割り当ては **240 ポート（16 ポート × 15 R-block）** であるため、  
> 1 R-block 限定では割り当ての 1/15 しか使用できず、家庭用ルーターとして実用的な  
> 同時接続数を確保できない。複数 R-block への対応は **Step 6 で必須実装** とする。

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

### Step 1: `calc_port_ranges` の RFC 7597 対応と中間レンジ計算関数の追加

**対象ファイル**: `src/map/port_set.rs`

#### 1-1. `calc_port_ranges` の式を RFC 7597 準拠に変更

現行の式 `Port = R * 2^(a+k) + j * 2^k + PSID`（PSID が低位 k ビット）を
RFC 7597 準拠の式 `Port = R * 2^(16-a) + PSID * 2^(16-a-k) + j`（PSID が中位 k ビット）に変更する。

- `R ∈ [1, 2^a - 1]`（高位 a ビット、1 以上）
- `j ∈ [0, 2^(16-a-k) - 1]`（低位ビット、任意）

**ループ変数の入れ替えが必要**（現行コードは逆転している）:

```rust
// 変更前（現行・誤り）
let r_count = 1u32 << (16 - a - k);  // R の上限として誤用
let j_count = 1u32 << a;             // j の上限として誤用

// 変更後（RFC 7597 準拠）
let r_count = 1u32 << a;             // R ∈ [1, 2^a - 1]
let j_count = 1u32 << (16 - a - k);  // j ∈ [0, 2^(16-a-k) - 1]
// capacity も連動して変更: (r_count as usize).saturating_sub(1) * j_count as usize
```

> **v6plus (a=4, k=8) では `2^a = 2^(16-a-k) = 16` が偶然一致するため総数テスト（240 ポート）は変更前後で通過するが、ポートの値そのものが変わる**（例: R=1, j=0, PSID=5 のポートは `4101 → 4176`）。`test_v6plus_port_formula` は新しい期待値に更新する。

**a=0 の特殊処理が必要**:  
a=0 のとき `R ∈ [1, 2^0-1] = [1, 0]` となりループが空になるため、ポートがゼロ件になる。  
a=0 の場合は R 次元を持たない特殊ケースとして、以下の方式で直接計算する:

```rust
if a == 0 {
    // R 次元なし: Port = PSID * 2^(16-k) + j, j ∈ [0, 2^(16-k)-1] (port=0 は除外)
    let block_size = 1u32 << (16 - k);
    let base = psid as u32 * block_size;
    // base == 0 (PSID=0, k=0) の場合 j=1 からスタート
    // それ以外は j=0 から
}
```

既存テスト `test_a0_k0_all_ports`（→ `[1..=65535]`）・`test_a0_port_formula` の期待値も新しい式に合わせて更新する（例: a=4, k=8, PSID=5, R=1, j=0 のポートは `4096 + 5*16 + 0 = 4176`）。

#### 1-2. `calc_staging_range` 関数の追加

`calc_staging_range(port_params: &PortParams) -> (u16, u16)`

- 戻り値: `(staging_min, staging_max)`
- `staging_min = 1 << (16 - port_params.psid_offset)`（ただし a=0 の場合は `1`）
- `port_count = 2u32.pow((16 - port_params.psid_offset - port_params.psid_length) as u32)`（1 R-block = `2^(16-a-k)` ポート）
- `staging_max = staging_min + port_count as u16 - 1`

> **a=0, k=0 の特殊処理**: `1 << 16` は u16 をオーバーフローするため、a=0 の場合は `staging_min=1, staging_max=65535` を直接返す（PSID が存在しないため全ポートがステージングレンジ）。

**テスト**:
- a=4, k=8 (v6plus): `staging_min=4096, port_count=16, staging_max=4111`
- a=6, k=6 (OCN): `staging_min=1024, port_count=16, staging_max=1039`
- a=0, k=0 (PSID なし): `staging_min=1, staging_max=65535`（特殊処理）

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
    if psid_length == 0 {
        // PSID なし（a=0, k=0 など）: 変換不要、かつ shift=16 でオーバーフローするため早期リターン
        return (0xFFFF, 0x0000);
    }
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

### Step 3: nftables masquerade ルールの変更

**対象ファイル**: `src/nftables/manager.rs`

`generate_ruleset` の `chain postrouting` を複数の `masquerade to :range` から単一の `masquerade to :staging_min-staging_max` に変更:

```nftables
chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "{tunnel_interface}" meta l4proto { tcp, udp }
        masquerade to :{staging_min}-{staging_max}
}
```

> **注意**: `snat to :{port_range}` は宛先 IP アドレスが必須で無効な文法となる。  
> `masquerade to :{port_range}` はインターフェースの IPv4 アドレスを自動使用するため正しい形式。

`generate_ruleset` のシグネチャ変更:

```rust
pub fn generate_ruleset(
    port_ranges: &[RangeInclusive<u16>],
    staging_range: (u16, u16),        // 追加
    tunnel_interface: &str,
    br_address: Ipv6Addr,
) -> String
```

`apply_ruleset` のシグネチャも同様に変更が必要（内部で `generate_ruleset` を呼び出すため）:

```rust
pub async fn apply_ruleset(
    executor: &impl CommandExecutor,
    port_ranges: &[RangeInclusive<u16>],
    staging_range: (u16, u16),        // 追加
    tunnel_interface: &str,
    br_address: Ipv6Addr,
) -> Result<(), MapEError>
```

> **`port_ranges` の役割**: `staging_range` は `chain postrouting` の masquerade ルールに使用する。  
> `port_ranges`（RFC 7597 準拠の実際の PSID ポート群）は引き続き `set port_ranges` の定義に使用し、  
> インバウンドフィルタリング（`chain prerouting` の許可判定）に利用する。シグネチャから削除しない。

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
# ポートマスク値の計算（16 進数、0x プレフィックス付きで tc コマンドに渡す）
# and_mask, or_value は calc_pedit_params が返す u16 値をそのまま使用（ネットワーク順＝ビッグエンディアン）
#
# staging range は 2 の累乗アラインのため u32 マスクで範囲指定可能:
#   range_mask = !(port_count - 1) & 0xFFFF
#   例: staging_min=0x1000, port_count=16 → range_mask=0xFFF0
#   → match tcp src 0x1000 0xfff0 で 0x1000〜0x100F に一致

# 1. clsact qdisc を設定（egress/ingress 共用、既存があれば replace）
tc qdisc replace dev {iface} clsact

# 2. egress: TCP 送信元ポート変換（staging_port → final_port）
#    staging range 内のパケットのみマッチ（u32 マスク範囲指定）
tc filter add dev {iface} egress protocol ip u32 \
    match ip protocol 6 0xff \
    match tcp src 0x{staging_min:04X} 0x{range_mask:04X} \
    action pedit ex \
        munge tcp sport and 0x{and_mask:04X} or 0x{or_value:04X} retain \
    pipe \
    action csum tcp

# 3. egress: UDP 送信元ポート変換
tc filter add dev {iface} egress protocol ip u32 \
    match ip protocol 17 0xff \
    match udp src 0x{staging_min:04X} 0x{range_mask:04X} \
    action pedit ex \
        munge udp sport and 0x{and_mask:04X} or 0x{or_value:04X} retain \
    pipe \
    action csum udp

# 4. ingress: TCP 宛先ポート逆変換（final_port → staging_port）
#    PSID ビットをクリアするだけで staging_port に戻る（staging は PSID ビット = 0 のため）
tc filter add dev {iface} ingress protocol ip u32 \
    match ip protocol 6 0xff \
    action pedit ex \
        munge tcp dport and 0x{and_mask:04X} retain \
    pipe \
    action csum tcp

# 5. ingress: UDP 宛先ポート逆変換
tc filter add dev {iface} ingress protocol ip u32 \
    match ip protocol 17 0xff \
    action pedit ex \
        munge udp dport and 0x{and_mask:04X} retain \
    pipe \
    action csum udp
```

> **ingress pedit が必要な理由**:  
> egress pedit は staging_port → final_port に変換するが、nftables MASQUERADE の conntrack は  
> staging_port を記録する。戻りパケットは dst_port = final_port で到着するため、conntrack が  
> マッチせず NAT 逆変換が機能しない。ingress pedit で `dport = dport & and_mask` を行うと  
> PSID ビットがクリアされ staging_port に復元される（staging ポートは PSID ビット = 0 が保証  
> されているため AND だけで正確に復元可能）。これにより conntrack が正常に動作する。

> **ingress pedit が全 TCP/UDP パケットに適用される前提**:  
> ingress pedit はプロトコルのみをマッチし、宛先ポートのレンジチェックは行わない。  
> MAP-E トンネルインターフェース（ip6tnl）上のパケットは BR によって転送制御されており、  
> RFC 7597 Section 8 に従い BR は CE の PSID に属するポートを持つパケットのみを転送する。  
> そのため、デカプセル後の dst_port はすべて PSID ポートレンジ内に収まることが保証される。  
> **本 ingress ルールはトンネルインターフェースにのみ適用し、WAN/LAN インターフェースには適用しないこと。**

**テスト**: `MockTcHandle` を用いたコマンド列検証（egress/ingress 両方）

---

### Step 5: `lifecycle.rs` への統合

**対象ファイル**: `src/daemon/lifecycle.rs`

`apply` に tc 適用ステップを追加:

```rust
// nftables masquerade（中間レンジへ）
let staging_range = calc_staging_range(&params.rule.port_params);
apply_ruleset(executor, &port_ranges, staging_range, ...).await?;

// tc pedit（PSID ビット埋め込み + ingress 逆変換）
tc.apply_psid_pedit(
    &config.tunnel_interface,
    params.rule.port_params.psid_offset,
    params.rule.port_params.psid_length,
    params.psid,
    staging_range.0,
    staging_range.1,
).await?;
```

`cleanup` で `tc.delete_psid_pedit(&config.tunnel_interface)` を呼ぶ。

> **注意**: `delete_psid_pedit` はインターフェース名のみ必要。`DaemonState` に `staging_range` を保持する必要はない。

`update` で PSID が変わった場合（`port_ranges` のみ変更のケースを含む）も tc ルールを再適用する:

```rust
// update 内: port_ranges のみ変更の場合
// staging_range は psid_offset/psid_length のみに依存（PSID 非依存）で変わらないが、
// or_value = psid << shift は PSID に依存するため tc ルールの再適用が必要
let staging_range = calc_staging_range(&new_params.rule.port_params);
apply_ruleset(executor, &new_port_ranges, staging_range, ...).await?;
tc.apply_psid_pedit(
    &config.tunnel_interface,
    new_params.rule.port_params.psid_offset,
    new_params.rule.port_params.psid_length,
    new_params.psid,
    staging_range.0,
    staging_range.1,
).await?;
```

> `apply_psid_pedit` は `tc qdisc replace` および `tc filter add` を使用するため、  
> 既存ルールがある場合は qdisc ごと置き換えられる（冪等）。

**統合テスト**: `full_lifecycle_integration.rs` に tc 操作込みの lifecycle テスト追加（tc が使えない環境ではスキップ）

---

### Step 6: 複数 R-block 対応（v6plus 本番利用に必須）

**背景**: Step 1〜5 の実装は nftables masquerade を 1 R-block（v6plus で 16 ポート）に限定する。  
v6plus の割り当ては **240 ポート（16 × 15 R-block）** であり、1 R-block 限定では割り当ての 1/15 しか使えない。  
家庭用ルーターとして実用的な同時接続数を確保するため、複数 R-block 対応が必要。

Phase 1 の制約は tc pedit にあるのではなく、**nftables masquerade（単一連続 port range のみ）** にある。  
tc pedit は R-block ごとにフィルタルールを定義することで複数 R-block を処理できるが、  
接続の新規確立時に nftables が複数の非連続 staging range に分散させる手段がない。  
複数 R-block 対応には nftables masquerade を置き換える以下のいずれかの実装が必要:

**Option A: eBPF (tc BPF) による実装（推奨）**
- tc filter に BPF プログラムをアタッチ（clsact qdisc はそのまま利用可能）
- BPF で「接続ごとの R-block 選択 → PSID ビット埋め込み → ポート書き換え」を一括実装し、nftables masquerade の staging を不要にする
- `bpf_csum_diff` / `bpf_l4_csum_replace` でチェックサムを安全に再計算
- 実装コスト: clang + BPF ヘルパーが必要

**Option B: nftables egress フック（Linux 5.17+）**
- `nftables egress hook` でポート変換を行う（tc egress と同等の位置で動作）
- nftables の式で PSID ビット操作が表現できるか要確認

> **Step 6 は Phase 2 として実装する。Step 1〜5（Phase 1）は動作確認・プロトタイプとして価値があるが、  
> プロダクション投入前に Step 6 Option A（eBPF）の完了が必要。**

---

## `DaemonState` への追加フィールド

`staging_range` は cleanup 時に不要（`delete_psid_pedit` はインターフェース名のみ使用）なので、`DaemonState` への追加フィールドはない。

`TcHandle` の実装インスタンスを `DaemonState` または呼び出し元で保持する設計にする。

---

## 影響範囲

| ファイル | 変更種別 |
|----------|---------|
| `src/map/port_set.rs` | `calc_port_ranges` 式を RFC 7597 準拠に変更 + `calc_staging_range` 関数追加 |
| `src/tc/mod.rs` | 新規 |
| `src/tc/manager.rs` | 新規（`TcHandle` trait + `TcManager` 実装、egress/ingress 両方） |
| `src/nftables/manager.rs` | `generate_ruleset` シグネチャ変更、masquerade ルール変更 |
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

1. **ip6tnl デバイスでの tc pedit 動作**: ip6tnl egress/ingress で tc filter が内側の IPv4 パケットヘッダを正しく参照・変換できるか要検証。カーネルによっては外側 IPv6 ヘッダを参照する場合がある。
2. **u32 ポート範囲マッチ**: staging range は 2 の累乗アラインのため `match tcp/udp src MASK` で解決可能（egress）。ingress 側は BR の PSID 強制に依存し範囲フィルタなし（トンネルインターフェース限定で適用するため許容）。
3. **チェックサムオフロード**: NIC のハードウェアオフロードが有効な場合の pedit との干渉
4. **ICMP 等**: TCP/UDP 以外のプロトコルの扱い（通常は PSID 対象外だが確認が必要）
5. **同時接続数の上限（Phase 1 制約）**: nftables masquerade が単一の連続 port range しか指定できないため、1 R-block = `2^(16-a-k)` ポート（v6plus で 16）が同時接続の上限。v6plus の割り当ては 240 ポート（16 × 15 R-block）なので Phase 1 では割り当ての 1/15 のみ使用可能。Step 6（eBPF）で nftables masquerade を置き換えることで解消する。
