# Aya eBPF 統合計画（MAP-E PSID ポート変換）

## 背景・目的

複数 R-block 対応の PSID ポート変換を eBPF (Aya) で実装する。

### 現状の制約

- nftables `masquerade to :range` は**単一連続レンジのみ**対応
- 複数の `masquerade to :range` ルールを並べても最初のルールしか適用されない

### eBPF で解決する理由

TC BPF プログラムは clsact qdisc にアタッチされ、パケットを Netfilter の前後で自由に書き換えられる。
BPF maps を使って接続ごとの R-block 選択と PSID ポートへの変換を実装することで、nftables の制約を完全に回避できる。

---

## 統合アプローチ比較

### Option A: Aya スケルトンへの移植

`cargo generate --git https://github.com/aya-rs/aya-template` が生成するワークスペース構成に現行プロジェクトを移植する方式。

```
mapecd/ (workspace root)
├── mapecd/          # 現行コード移植先
├── mapecd-ebpf/     # BPF プログラム
├── mapecd-common/   # 共有型
└── xtask/           # ビルドヘルパー (cargo xtask build-ebpf)
```

**メリット**:

- Aya 公式推奨構成で長期メンテナンスが容易
- xtask が BPF クロスコンパイルを自動処理
- `cargo xtask build-ebpf` で開発体験が良い

**デメリット**:

- 既存 ~13,500 行のコード・テスト・CI を全て移動する必要あり
- パッケージ名・パス変更によるリグレッションリスク大
- 移植作業コストが本質的な機能追加と分離できない

### Option B: カスタム組み込み（Cargo Workspace 化）★採用

既存コードはそのままに、`mapecd-ebpf/` と `mapecd-common/` だけを新たな Workspace メンバーとして追加する。

```
mapecd/ (workspace root)
├── Cargo.toml           # [workspace] 追加（既存パッケージはそのまま残す）
├── src/                 # 既存コード変更なし
├── build.rs             # 新規: BPF コンパイル (aya-build)
├── mapecd-ebpf/         # 新規クレート: BPF プログラム
│   ├── Cargo.toml       # target = bpfel-unknown-none
│   └── src/
│       ├── main.rs      # BPF プログラムエントリ
│       ├── egress.rs    # TC BPF egress 実装
│       ├── ingress.rs   # TC BPF ingress 実装
│       └── checksum.rs  # L4 チェックサム更新ヘルパー
└── mapecd-common/       # 新規クレート: 共有型 (BPF ↔ userspace)
    ├── Cargo.toml
    └── src/
        └── lib.rs       # PsidConfig
```

**メリット**:

- 既存コード・テスト・CI への影響最小
- `aya-build` を `build.rs` に追加するだけで BPF クロスコンパイルが完結
- BPF クレートの分離でスケルトンと同等の構造を実現
- 将来 Option A（xtask 方式）への移行も容易

**デメリット**:

- `xtask` が使えないため `build.rs` で BPF コンパイルを管理（若干手動）

---

## アーキテクチャ設計

### パケット処理フロー（eBPF 版）

```
[送信: LAN → Internet]
  LAN ホスト (192.168.1.x:src_port / ICMP identifier)
      │
  Netfilter POSTROUTING (masquerade、ポート制約なし)
      │ src_ip  = CE-IPv4
      │ src_port / ICMP identifier = staging_val (ephemeral range、PSID 制約なし)
      ↓
  TC BPF egress (tunnel interface)
      │ TCP/UDP: src_port (= staging_val) → psid_val を決定的計算
      │ ICMP Echo Request (type 8): identifier (= staging_val) → psid_val を同一計算
      │   block_size  = 1 << (16-a-k)
      │   idx         = staging_val - staging_min
      │   R           = idx / block_size + 1
      │   j           = idx % block_size
      │   psid_val    = R * 2^(16-a) + PSID * 2^(16-a-k) + j
      │ フィールド書き換え + チェックサム更新
      │   TCP/UDP: bpf_l4_csum_replace(..., BPF_F_PSEUDO_HDR)
      │   ICMP: bpf_l4_csum_replace(..., 0)  ← pseudo header なし
      ↓
  IPv6 カプセル化 → WAN へ

[受信: Internet → LAN]
  IPv6 デカプセル化
      │ dst_port / ICMP identifier = psid_val (PSID 準拠)
      ↓
  TC BPF ingress (tunnel interface)
      │ TCP/UDP: dst_port (= psid_val) → staging_val を決定的逆算
      │ ICMP Echo Reply (type 0): identifier (= psid_val) → staging_val を同一逆算
      │   j            = psid_val & (block_size - 1)
      │   R            = psid_val >> (16-a)
      │   idx          = (R - 1) * block_size + j
      │   staging_val  = staging_min + idx
      │ フィールド書き換え + チェックサム更新
      ↓
  Netfilter PREROUTING (conntrack)
      │ staging_val で conntrack マッチ → DNAT
      ↓
  LAN ホストへ転送
```

### staging range の定義（全単射の前提）

nftables masquerade には **MAP-E PSID ポート群と全単射になる単一連続レンジ** を与える。
全単射のため BPF side で state map は不要（決定的計算のみ）。

```
staging_min  = 1 << (16 - a)
block_size   = 1 << (16 - a - k)      // 1 R-block あたりのポート数
num_r_blocks = (1 << a) - 1           // R ∈ [1, 2^a - 1]
total_ports  = num_r_blocks * block_size
staging_max  = staging_min + total_ports - 1
```

例: v6plus (a=4, k=8, PSID=5):

- staging_min=4096, block_size=16, num_r_blocks=15, total_ports=240, staging_max=4335

> a=0 の特殊ケース: `staging_min=1, staging_max=65535`（R 次元なし、全ポート）

```nftables
chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "ip6tnl0" meta l4proto { tcp, udp, icmp } masquerade to :{staging_min}-{staging_max}
}
```

> nftables masquerade は TCP/UDP のポートと同様に ICMP Echo Identifier を staging range 内に割り当てる（netfilter の `nf_nat_proto_icmp` が `NF_NAT_RANGE_PROTO_SPECIFIED` を尊重する）。  
> ICMP Echo 以外（Destination Unreachable 等）は Identifier フィールドを持たないため masquerade の対象外となる（netfilter が type を見て処理を分岐する）。

`set port_ranges` は eBPF 統合後も `generate_ruleset` のシグネチャとテーブル定義には残すが、postrouting の masquerade ルールが単一 staging range ルールに置き換わるため `set port_ranges` を参照するルールは存在しなくなる（定義のみ残る形になる）。将来の監視ツール参照等を考慮して定義は保持するが、不要であれば Step E5 で削除しても構わない。

### 全単射の計算式

**Egress（staging_port → psid_port）**:

```
idx        = staging_port - staging_min   // 0-based 連番
R          = idx / block_size + 1
j          = idx % block_size
psid_port  = R * (1 << (16-a)) + psid * (1 << (16-a-k)) + j
```

**Ingress（psid_port → staging_port）**:

```
j            = psid_port & (block_size - 1)
R            = psid_port >> (16 - a)
idx          = (R - 1) * block_size + j
staging_port = staging_min + idx
```

検証例（a=4, k=8, PSID=5, staging_min=4096）:

| staging | idx | R   | j   | psid_port             |
| ------- | --- | --- | --- | --------------------- |
| 4096    | 0   | 1   | 0   | 4096+80+0 = **4176**  |
| 4111    | 15  | 1   | 15  | 4096+80+15= **4191**  |
| 4112    | 16  | 2   | 0   | 8192+80+0 = **8272**  |
| 4335    | 239 | 15  | 15  | 61440+80+15=**61535** |

逆算: psid_port=8272 → j=8272&15=0, R=8272>>12=2, idx=16, staging=4112 ✓

### BPF Maps 設計

state map は不要。CONFIG_MAP のみ。

```
CONFIG_MAP (BpfArray, 1 entry)
  └── PsidConfig { offset: u8, length: u8, block_shift: u8, _pad: u8, psid: u16, staging_min: u16, staging_max: u16 }
```

> **`staging_max` / `block_shift` をマップに持つ理由**: どちらも BPF 内で `offset`/`length` から毎パケット計算することは可能だが、ユーザースペース側で一度だけ算出して格納することで BPF プログラムを単純化できる。特に `block_shift` は egress/ingress の全計算ステップでシフト量として参照されるため、CONFIG_MAP から直接読み出す方が Verifier が追う演算数を減らせる。BPF 内では乗除算を使わず **ビットシフト・ビットマスク** のみで全単射計算を実装すること（`block_size` は常に `1 << block_shift` の 2 のべき乗であるため代替可能。BPF Verifier は変数による汎用除算を原則リジェクトする）。

### BPF プログラム設計

```
tc_egress (SchedClassifier, "tc_egress"):
  1. IPv4 ヘッダを解析し L4 プロトコルを確認（IHL フィールドを読んで L4 オフセットを動的計算）
  2. TCP/UDP: src_port (= staging_val) を読み取り
     ICMP Echo Request (type 8): identifier (= staging_val) を読み取り
     それ以外: TC_ACT_OK でスルー
  3. CONFIG_MAP から PsidConfig を取得
  3.5. offset == 0 → TC_ACT_OK でスルー（R 次元なし、ポート変換不要）
       ※ offset=0 のままステップ 5 に進むと `1u16 << (16 - offset)` がシフト量 16 となり
         Rust でパニック/UB になるため、この早期リターンは必須
  4. staging_val が [staging_min, staging_max] の範囲外 → TC_ACT_OK でスルー
  5. idx      = staging_val - staging_min
     R        = (idx >> block_shift) + 1
     j        = idx & ((1u16 << block_shift) - 1)
     psid_val = R * (1u16 << (16 - offset)) + psid * (1u16 << block_shift) + j
  6. フィールド = psid_val に書き換え
  7. チェックサム更新:
       TCP/UDP: bpf_l4_csum_replace(..., BPF_F_PSEUDO_HDR)
       ICMP:    bpf_l4_csum_replace(..., 0)  ← pseudo header なし
  8. TC_ACT_OK を返す

tc_ingress (SchedClassifier, "tc_ingress"):
  1. IPv4 ヘッダを解析し L4 プロトコルを確認（IHL フィールドを読んで L4 オフセットを動的計算）
  2. TCP/UDP: dst_port (= psid_val) を読み取り
     ICMP Echo Reply (type 0): identifier (= psid_val) を読み取り
     それ以外: TC_ACT_OK でスルー
  3. CONFIG_MAP から PsidConfig を取得
  3.5. offset == 0 → TC_ACT_OK でスルー（R 次元なし、逆算不要）
       ※ egress と同様、offset=0 のままステップ 4 に進むと `psid_val >> (16 - offset)` がシフト量 16 となり UB
  4. R 検証: (psid_val >> (16 - offset)) == 0 → TC_ACT_OK でスルー（R=0 は未割り当てブロック）
     PSID ビット検証: ((psid_val >> block_shift) & ((1u16 << length) - 1)) != psid → TC_ACT_OK でスルー
  5. j           = psid_val & ((1u16 << block_shift) - 1)
     R           = psid_val >> (16 - offset)
     idx         = ((R - 1) << block_shift) | j
     staging_val = staging_min + idx
  6. フィールド = staging_val に書き換え
  7. チェックサム更新（egress と同様、ICMP は BPF_F_PSEUDO_HDR なし）
  8. TC_ACT_OK を返す
```

---

## モジュール構成（追加分）

```
src/
├── ebpf/               # 新規モジュール
│   ├── mod.rs          # pub use EbpfManager
│   └── manager.rs      # EbpfManager: ロード・リンク・CONFIG_MAP 更新
└── daemon/
    └── lifecycle.rs    # EbpfManager を apply/cleanup/update に統合
```

`EbpfManager` の責務:

```rust
pub struct EbpfManager { /* Aya Ebpf ハンドル + TC リンクハンドル */ }

impl EbpfManager {
    /// BPF ELF をロードし CONFIG_MAP を初期化する
    pub async fn load(params: &PsidConfig) -> Result<Self, MapEError>;
    /// clsact qdisc をセットし egress/ingress TC プログラムをリンクする
    pub async fn link_tc(&mut self, interface: &str) -> Result<(), MapEError>;
    /// CONFIG_MAP のみ更新（PSID 変更時に再リンク不要、state map なし）
    pub async fn update_config(&mut self, params: &PsidConfig) -> Result<(), MapEError>;
    /// TC リンクを解除し qdisc を削除する
    pub async fn unlink_tc(&mut self) -> Result<(), MapEError>;
}
```

---

## 実装ステップ

### Step E1: Workspace 化と共通クレート

**対象**: `Cargo.toml`, `mapecd-common/`（新規）

- `Cargo.toml` に `[workspace]` セクションと `members` を追加
- `mapecd-common/src/lib.rs` に以下を定義:
  - `#![no_std]`
  - `#[repr(C)] struct PsidConfig { offset: u8, length: u8, block_shift: u8, _pad: u8, psid: u16, staging_min: u16, staging_max: u16 }`
    - `staging_min` はユーザースペース側で `1 << (16 - offset)` として計算して渡す（a=0 は特殊処理: 1 を直接代入）
    - `staging_max` はユーザースペース側で `staging_min + ((1 << offset) - 1) * (1 << (16 - offset - length)) - 1` として計算して渡す（a=0 は特殊処理: 65535 を直接代入）
    - `block_shift` はユーザースペース側で `16 - offset - length` として計算して渡す（a=0 は特殊処理: 0 を代入。BPF Verifier 対応のためシフト量を事前計算して格納する）
    - **入力バリデーション**: `PsidConfig::from()` の変換時に `offset + length <= 16` を assert または返り値 `Result` でチェックし、不正なパラメータで u8 アンダーフローが発生しないことを保証すること
  - state map 用の key/value 型は不要（決定的計算のため）

**テスト**: `mapecd-common` の型サイズ・アライメント確認

---

### Step E2: BPF クレートセットアップ

**対象**: `mapecd-ebpf/`（新規）, `mapecd-ebpf/.cargo/config.toml`（新規）, `rust-toolchain.toml`（新規）, `build.rs`（新規）, `Dockerfile.test`（更新）

`Dockerfile.test` への追加（BPF ビルド依存）:

```dockerfile
RUN apt-get update && apt-get install -y \
    nftables \
    iproute2 \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*
```

> **注意**: `rust-toolchain.toml` をワークスペースルートに置くことで `rustup` が自動的に nightly toolchain を取得・使用する。`Dockerfile.test` で rust を `rustup` 経由でインストールしている場合は追加対応不要。`apt` などで rust をインストールしている場合は nightly チャンネルを明示的にセットアップすること（例: `rustup toolchain install nightly`）。

`mapecd-ebpf/Cargo.toml`:

```toml
[package]
name = "mapecd-ebpf"
version = "0.1.0"
edition = "2024"

[dependencies]
aya-ebpf = "0.1"
mapecd-common = { path = "../mapecd-common" }

[[bin]]
name = "mapecd-ebpf"
path = "src/main.rs"
```

`rust-toolchain.toml`（ワークスペースルート）:

> **注意**: `mapecd-ebpf/.cargo/config.toml` の `[unstable] build-std = ["core"]` は nightly Rust の機能であり stable では使用不可。ワークスペースルートに `rust-toolchain.toml` を追加して nightly チャンネルを固定する必要がある。デーモン本体のコンパイルも nightly で行われることになるが、nightly での動作確認を Step E2 の完了基準に含めること。
>
> **nightly チャンネルの安定化**: `channel = "nightly"` のまま運用すると日次ビルドの更新で突発的にビルドが壊れるリスクがある。CI では必ず動作確認済みの日付で `channel = "nightly-YYYY-MM-DD"` に固定すること。Step E2 の完了時点で確認した日付を記入し、以降のアップデートは意図的なタイミングで行う。

```toml
[toolchain]
channel = "nightly-YYYY-MM-DD"  # Step E2 完了時に実際の日付に置き換える
```

`mapecd-ebpf/.cargo/config.toml`:

> **注意**: この `.cargo/config.toml` は `mapecd-ebpf/` サブディレクトリ直下に配置する。ワークスペースルートに置くと `bpfel-unknown-none` ターゲットの設定がデーモン本体のビルドにも波及しビルドが壊れる。`aya-build::build_ebpf_programs()` はワークスペースルートの `build.rs` から cargo を起動するが、このとき `mapecd-ebpf/` のサブディレクトリ設定が自動的に参照されるため問題ない。

```toml
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]
```

`build.rs`:

> **注意**: `aya-build` は Linux 専用のため、非 Linux 環境（macOS 等）でのビルドを守るために `#[cfg(target_os = "linux")]` で条件分岐すること。

```rust
fn main() {
    #[cfg(target_os = "linux")]
    {
        use aya_build::cargo_metadata;
        let metadata = cargo_metadata().unwrap();
        aya_build::build_ebpf_programs(&metadata, &["mapecd-ebpf"]).unwrap();
    }
}
```

`Cargo.toml` (root) への追加依存:

> **注意**: `aya` / `aya-build` は Linux 専用。既存コードの慣習に従い Linux 限定セクションに追加すること。

```toml
[target.'cfg(target_os = "linux")'.build-dependencies]
aya-build = "0.1"

[target.'cfg(target_os = "linux")'.dependencies]
aya = { version = "0.13", features = ["async_tokio"] }
```

---

### Step E2.5: ICMP masquerade 動作確認（PoC）

**対象**: テスト環境（Docker + netns）

> **実施タイミング**: E2 完了（BPF ビルド環境が整った時点）直後、E3 着手前に行うこと。  
> `masquerade to :range` が ICMP Echo Identifier に作用するかどうかは **計画全体の前提** であり、  
> これが動作しない場合は ICMP Identifier の割り当てを BPF 側で直接管理する別アーキテクチャが必要になる。  
> E3〜E6 を実装し終えた後（Step E7 統合テスト）に発覚すると手戻りが大きいため先行検証する。

確認手順（最小 PoC）:

1. netns 内で nftables を起動し `masquerade to :4096-4335` を設定
2. `ping` 等で ICMP Echo Request を送出し、`tcpdump` で Identifier が staging range 内に変換されているか確認
3. 動作確認: Identifier が `[4096, 4335]` に収まっていれば本計画のアーキテクチャで進める
4. 動作しない場合: 以下の変更が必要になる（TCP/UDP のみ対応として ICMP を初期実装のスコープ外に留めることを推奨）
   - **E3 への影響**: egress の ICMP Echo Request (type 8) / ingress の ICMP Echo Reply (type 0) の Identifier 変換処理を実装しない（それ以外の type と同様に TC_ACT_OK でスルー）
   - **E5 への影響**: masquerade ルールの l4proto から `icmp` を削除し `{ tcp, udp }` のみとする

**完了基準**: 確認結果をこのドキュメントのコメントまたは notes として記録し、以降のステップの ICMP 対応方針を確定させること。

---

### Step E3: BPF プログラム実装

**対象**: `mapecd-ebpf/src/`

`main.rs` — BPF Map 定義と #[panic_handler]:

```rust
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, classifier};
use aya_ebpf::maps::Array;
use mapecd_common::PsidConfig;

#[map]
static CONFIG_MAP: Array<PsidConfig> = Array::with_max_entries(1, 0);
```

`egress.rs` — tc_egress 実装（要点）:

- `CONFIG_MAP` から `PsidConfig` を読み取り
- TCP/UDP: `src_port`、ICMP Echo Request (type 8): `identifier` を `staging_val` として読み取り
- それ以外の L4 プロトコル / ICMP type → TC_ACT_OK でスルー
- `staging_val` が `[staging_min, staging_max]` 外 → TC_ACT_OK でスルー（`staging_max` は CONFIG_MAP から取得）
- 決定的計算で `psid_val` を算出（BPF map lookup 不要）
- TCP/UDP: `bpf_l4_csum_replace(..., BPF_F_PSEUDO_HDR)` でチェックサム更新
- ICMP: `bpf_l4_csum_replace(..., 0)` でチェックサム更新（pseudo header なし）

`ingress.rs` — tc_ingress 実装（要点）:

- `CONFIG_MAP` から `PsidConfig` を読み取り
- TCP/UDP: `dst_port`、ICMP Echo Reply (type 0): `identifier` を `psid_val` として読み取り
- それ以外の L4 プロトコル / ICMP type → TC_ACT_OK でスルー
- R=0 検証: `psid_val >> (16-a) == 0` → TC_ACT_OK でスルー（R=0 は未割り当てブロック。PSID ビットが偶然一致するポートによるアンダーフローを防ぐ）
- PSID ビット検証で自 CE の PSID に属するフィールドか確認
- 決定的逆算で `staging_val` を算出（BPF map lookup 不要）
- フィールド書き換え + チェックサム更新（ICMP は BPF_F_PSEUDO_HDR なし）

`checksum.rs` — チェックサム更新ヘルパー:

- TCP/UDP 用: `bpf_l4_csum_replace(ctx, offset, old_val, new_val, BPF_F_PSEUDO_HDR)` を呼ぶラッパー
- ICMP 用: `bpf_l4_csum_replace(ctx, offset, old_val, new_val, 0)` を呼ぶラッパー（pseudo header なし）
  - ICMP checksum オフセット = IPv4 ヘッダ長 + 2、Identifier オフセット = IPv4 ヘッダ長 + 4

---

### Step E4: Userspace EbpfManager 実装

**対象**: `src/ebpf/manager.rs`（新規）

```rust
use aya::{Ebpf, programs::{SchedClassifier, TcAttachType, tc::TcLink}};
use aya::maps::Array;
use mapecd_common::PsidConfig;

pub struct EbpfManager {
    ebpf: Ebpf,
    interface: Option<String>,
    egress_link: Option<TcLink>,   // drop すると egress filter が自動削除される
    ingress_link: Option<TcLink>,  // drop すると ingress filter が自動削除される
}

impl EbpfManager {
    pub async fn load(params: &PsidConfig) -> Result<Self, MapEError> { ... }
    pub async fn link_tc(&mut self, interface: &str) -> Result<(), MapEError> { ... }
    pub async fn update_config(&mut self, params: &PsidConfig) -> Result<(), MapEError> { ... }
    pub async fn unlink_tc(&mut self) -> Result<(), MapEError> { ... }
}
```

> **`PsidConfig` 変換の実装場所**: `mapecd-common` は `#![no_std]` のため `MapeParams` に依存できない。`PsidConfig::from(&MapeParams)` に相当する変換（`offset`/`length`/`psid` 取り出しと `staging_min`/`staging_max`/`block_shift` の算出）は `src/ebpf/manager.rs` 内に `impl From<&MapeParams> for PsidConfig` として実装する。`MapeParams` から必要なフィールドは `params.rule.port_params.psid_offset`（= a）、`params.rule.port_params.psid_length`（= k）、`params.psid`。

`load()`:

- `include_bytes!(concat!(env!("OUT_DIR"), "/mapecd-ebpf"))` で BPF ELF をバインド（`aya-build` のバージョンによっては `"/bpfel-unknown-none/release/mapecd-ebpf"` 等のサブパスになる場合があるため、実装時に OUT_DIR の内容を確認すること）
- `Ebpf::load(bytes)` でロード
- `CONFIG_MAP` を初期化

`link_tc()`:

- `aya::programs::tc::qdisc_add_clsact(interface)` で clsact qdisc を追加（既存の場合はエラーを無視）
- `SchedClassifier` プログラムを `TcAttachType::Egress` / `Ingress` でアタッチし、返却された `TcLink` をそれぞれ `self.egress_link` / `self.ingress_link` に格納する（drop するとフィルタが自動削除されるため、`EbpfManager` が生きている間は保持し続けること）

`update_config()`:

- `CONFIG_MAP` の 0 番エントリを新しい `PsidConfig` で上書き
- 変換は決定的計算のため state map クリア不要

`unlink_tc()`:

- `self.egress_link` / `self.ingress_link` を `None` にして drop（Aya が自動で filter 削除）
- clsact qdisc 自体は残存する（次回 `link_tc()` 時に既存 qdisc を再利用）
- デーモン再起動時の古いフィルタ残留に備え、`link_tc()` の冒頭で既存の mapecd フィルタを削除（または上書き）する処理を入れること

テスト: `NftExecutor` / `MockExecutor` パターンと同様に **`EbpfHandle` トレイト** を定義し、`EbpfManager` に実装する。`lifecycle.rs` のテストでは `MockEbpfHandle` に差し替えられる形にする。トレイトには最低限 `load`, `link_tc`, `update_config`, `unlink_tc` を含める。

---

### Step E5: nftables masquerade の staging range 変更

**対象**: `src/nftables/manager.rs`

`generate_ruleset` に `staging_range: (u16, u16)` 引数を**追加**し、postrouting chain の masquerade ルール生成部分を単一 staging range に変更する:

```nftables
# eBPF 版: 全 R-block をカバー
# ICMP masquerade の動作確認（Step E2.5）が OK の場合: { tcp, udp, icmp }
# NG の場合（ICMP スコープ外）: { tcp, udp }
oifname "ip6tnl0" meta l4proto { tcp, udp, icmp } masquerade to :{staging_min}-{staging_max}
# 例: v6plus a=4, k=8 → masquerade to :4096-4335
```

`port_ranges` 引数はシグネチャから削除しない（`set port_ranges` のテーブル定義生成にそのまま使用する）。ただし eBPF 統合後は `set port_ranges` を参照するルールが存在しなくなるため、削除する場合はシグネチャから取り除いても問題ない（アーキテクチャ設計の `set port_ranges` の取り扱いも参照すること）。

`generate_ruleset` のシグネチャ変更に伴い、以下の変更も連鎖する:

- **`apply_ruleset()`**（同ファイル内）: `staging_range: (u16, u16)` 引数を追加し、`generate_ruleset` 呼び出しに渡す。
- **`lifecycle.rs` の `apply_ruleset()` 呼び出し箇所**: `PsidConfig` または `MapeParams` から算出した `staging_range` を渡すように変更する。

既存テストを新しい staging range 算出に合わせて更新する。`src/nftables/manager.rs` のテストに加え、`src/daemon/lifecycle.rs` の `test_update_port_ranges_only_calls_nftables` 等、`port_ranges` ベースのテストも更新対象に含まれる。

---

### Step E6: lifecycle.rs / runner.rs への統合

**対象**: `src/daemon/lifecycle.rs`、`src/daemon/state.rs`、`src/daemon/runner.rs`

`apply()` への追加:

```rust
// eBPF ロード + TC リンク（nftables 適用より先、トンネル作成より後に実施）
let psid_config = PsidConfig::from(&params);
let mut ebpf = EbpfManager::load(&psid_config).await?;
ebpf.link_tc(&config.tunnel_interface).await?;
state.ebpf = Some(ebpf);
// ← この後に nftables apply_ruleset を呼ぶ（staging range に切り替わる前に BPF がリンク済みであること）
```

> **apply() のステップ順序**: BPF のリンクはトンネルインターフェース（ip6tnl0）が存在していることが前提なので、既存の **step3（トンネル作成）の後**に配置し、**step6（nftables 適用）の前**に配置すること（step 5.5 相当）。nftables masquerade が staging range に切り替わった直後に BPF がまだリンクされていない状態だと、staging ポートのままパケットが送出されてしまう。

`update()` への追加:

```rust
// update() の各分岐の末尾（成功時）に追加する。
// - ce_ipv6 / br_address 変化時 → recreate_tunnel_and_apply() 内で BPF を再ロード・再リンクするため
//   update_config() 呼び出しは不要（CONFIG_MAP は load() 時に初期化される）。
// - ipv4 変化時 → トンネルは維持されるが新しい PsidConfig で CONFIG_MAP を更新する。
// - else（PSID のみ変化）→ CONFIG_MAP のみ更新。nftables は staging range 変更なしで再適用。
//
// 共通処理として以下を update() 末尾（各分岐の成功後）に配置する:
if let Some(ebpf) = &mut state.ebpf {
    let psid_config = PsidConfig::from(&new_params);
    ebpf.update_config(&psid_config).await?;
}
```

> **update() 各分岐と BPF 処理の対応**:
> - `ce_ipv6` / `br_address` 変化 → `recreate_tunnel_and_apply()` を呼ぶ分岐。BPF は `recreate_tunnel_and_apply()` 内で完全再ロード・再リンクされる（`load()` 時に CONFIG_MAP 初期化済み）。上記 `update_config()` 呼び出しはその後に実行されるが、同一パラメータの二重書き込みとなり実害なし。処理の明確さを優先するなら `recreate_tunnel_and_apply()` を呼ぶ分岐では `update_config()` をスキップする条件分岐を入れてもよい（どちらでも動作する）。
> - `ipv4` 変化 → トンネルは維持。`update_config()` で新しい IPv4 に対応した `PsidConfig` を反映する（staging_min/max/block_shift は a/k に依存するため内容は変わらないが、統一的に更新する）。
> - `else`（PSID のみ変化）→ `apply_step6_nftables` を呼ぶが staging range は a/k 依存のため生成される nftables ルールは実質同一（冪等）。`update_config()` で PSID 値を CONFIG_MAP に反映する。

> **update() の適用範囲**: `update()` は PSID・プレフィックス等が変化するケースを想定する。`a`/`k` が変化する（MAP-E ルール自体が別ルールに切り替わる）場合はトンネルインターフェースの再作成を伴うため、`cleanup()` → `apply()` の再構成サイクルで対応すること。`update()` での `a`/`k` 変化は想定しない。
>
> **`a`/`k` 変化の検出と分岐（`runner.rs` および `has_changed()`）**: 既存の `apply_if_ready()` は `has_changed()` が真なら `update()` を呼ぶが、`has_changed()` は `port_ranges` の変化を検出しても `a`/`k` 変化なのか PSID のみの変化なのかを区別できない。以下の 2 点を合わせて修正すること:
>
> **① `has_changed()` に `port_params` 比較を追加する**（`lifecycle.rs`）:
> ```rust
> pub fn has_changed(old: &MapeParams, new: &MapeParams) -> bool {
>     old.ce_ipv6 != new.ce_ipv6
>         || old.ipv4 != new.ipv4
>         || old.psid != new.psid
>         || old.br_address != new.br_address
>         || old.port_ranges != new.port_ranges
>         || old.rule.port_params != new.rule.port_params  // ← 追加
> }
> ```
> 既存の `has_changed` テスト（5 件）に加え、`port_params` 変化を検出するテストケースを追加すること。
>
> **② `apply_if_ready()` に `a`/`k` 変化時の分岐を追加する**（`runner.rs`）:
>
> 1. **`a`/`k` 変化**: `old.rule.port_params != new.rule.port_params` を検出し、`update()` を呼ばず `cleanup()` → `apply()` を実行する
> 2. **PSID のみ変化**（`a`/`k` 同一）: `update()` → `update_config()` のみ
> 3. **CE/BR/tunnel 変化**（`a`/`k` 同一）: `update()` → `recreate_tunnel_and_apply()` → 内部で BPF 再リンク
>
> `a`/`k` の比較は `MapeParams.rule.port_params`（`PortParams { psid_offset, psid_length }`）を直接比較することで追加フィールド不要で実現できる。

> **`recreate_tunnel_and_apply()` での BPF 再リンク**: 既存の `update()` はプレフィックス・BR アドレス等の変化時にトンネルを削除・再作成する `recreate_tunnel_and_apply()` を直接呼び出す。トンネル再作成によって BPF アタッチメントが無効になるため、`recreate_tunnel_and_apply()` 内でも BPF の再リンクが必要。処理順序は以下の通り：
> 1. BPF アンリンク（nftables cleanup の前）
> 2. nftables 削除
> 3. トンネル削除 → 再作成
> 4. BPF 再ロード + リンク（nftables 再適用の前）
> 5. nftables 再適用
>
> `recreate_tunnel_and_apply()` の実装時に上記ステップを統合すること。`state.ebpf` が `Some` の場合のみ BPF 再リンクを行い、`None` の場合（BPF 未使用環境）はスキップする。
>
> **部分失敗時の扱い**: ステップ途中でエラーが発生した場合はデーモンをハードエラーとして終了する（nftables が staging range を使っている状態で BPF がない中途半端な状態で運用継続しない）。具体的には ④ BPF 再リンクに失敗した場合、⑤ nftables 再適用を実施せずにエラーを返し、呼び出し元がデーモン終了シーケンスを実行すること。

`cleanup()` への追加:

> **cleanup() のステップ順序**: `apply()` の逆順で実施する。nftables ルールを先に削除（または元の PSID ポート範囲に戻す）してから BPF をアンリンクすること。先に BPF をアンリンクすると、nftables masquerade がまだ staging range を使い続けている間にポート変換が行われなくなり staging ポートのままパケットが WAN に漏れる。

```rust
// 1. nftables を先に元に戻す（または削除する）
cleanup_nftables(...).await.ok();
// 2. BPF アンリンク
if let Some(mut ebpf) = state.ebpf.take() {
    ebpf.unlink_tc().await.ok(); // エラーはログのみ
}
```

`DaemonState` への追加フィールド（`src/daemon/state.rs`）:

> **注意**: `EbpfManager` は Linux 専用のため `#[cfg(target_os = "linux")]` ガードが必要。`src/ebpf/mod.rs` のモジュール宣言・`EbpfManager` の型定義・`DaemonState` のフィールド・`lifecycle.rs` および `runner.rs` での参照箇所すべてに付与すること。既存コードの `daemon/mod.rs`・`runner.rs` のパターンに従う。

```rust
#[cfg(target_os = "linux")]
pub ebpf: Option<EbpfManager>,
```

**systemd サービスへの `CAP_BPF` 付与**:

`EbpfManager::load()` は `CAP_BPF` + `CAP_NET_ADMIN` を必要とする。デーモンを非 root で動作させる場合は systemd unit ファイルに以下を追加すること:

```ini
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
```

（既存 unit で `CAP_NET_ADMIN` が付与済みの場合は `CAP_BPF` の追加のみでよい）

---

### Step E7: テスト

**単体テスト**:

- `mapecd-common`: 型サイズ・フィールドオフセット確認（`std::mem::size_of`, `offset_of!`）
- `EbpfManager`: `EbpfHandle` トレイトと `MockEbpfHandle` を使い `lifecycle.rs` の apply/update/cleanup を検証
- `has_changed()`: `port_params`（a/k）変化の検出テストケースを追加（`test_has_changed_port_params` 等）
- `apply_if_ready()`: a/k 変化時に `cleanup() → apply()` がルーティングされることを確認するテストを追加

**統合テスト** (`tests/ebpf_integration.rs`):

- Linux + CAP_BPF + netns が使える環境でのみ実行 (`#[cfg(target_os = "linux")]`)
- ネットワーク名前空間内で TC BPF を実際にアタッチし、TCP/UDP ポート変換および ICMP Echo Identifier 変換が正しく動作することを確認
- 既存 `full_lifecycle_integration.rs` に eBPF 有効フラグを追加

---

## 前提条件・注意事項

- **ビルド環境**: `clang` + LLVM が必要（`bpfel-unknown-none` ターゲットへのクロスコンパイル）。`Dockerfile.test` に `clang` および `llvm` パッケージを追加すること。docker-compose.test.yml はすでに `privileged: true` のため `CAP_BPF` は付与済み。nightly Rust toolchain が必要（Step E2 参照）。
- **実行環境**: Linux kernel 5.10+（BTF サポート）、`CAP_BPF` + `CAP_NET_ADMIN` 権限
- **TC BPF が見るパケット**: ip6tnl0 の TC egress/ingress フックは、トンネルドライバの xmit より前（egress）/ デカプセル後（ingress）に発火するため、BPF プログラムが見るのは**内側の IPv4 パケット**（外側 IPv6 ヘッダは含まない）
- **a=0 の特殊ケース**: `offset=0` の場合は R 次元が存在せずポート変換は不要のため、BPF プログラムは設定読み取り後に `a == 0` を検出し TC_ACT_OK でスルーする。ユーザースペース側では `1 << (16-a)` の計算が `1 << 16` となり u16 オーバーフローするため、a=0 の場合は `staging_min = 1` を直接代入する特殊分岐が必要。
- **staging range 算出**: `staging_min = 1 << (16-a)`, `staging_max = staging_min + (2^a - 1) * 2^(16-a-k) - 1`（a=0 は特殊処理: [1, 65535]）
- **フラグメントパケット**: 初期実装では L4 ヘッダが読めないフラグメントは TC_ACT_OK でスルー。TCP/UDP の後続フラグメントにはポートフィールドが存在しないため BPF がスルーしても問題ない。ただし ICMP Echo Request が（まれに）フラグメントされた場合、最初のフラグメントの Identifier は BPF で変換されるが、後続フラグメントは変換されずに送出される。緩和策として、nftables で TCP MSS クランプ（`tcp flags syn tcp option maxseg size set rt mtu`）および IPv4 DF ビット設定を行い、フラグメント発生自体を抑制することを推奨する。
- **IPv4 ヘッダオプション（IHL > 5）**: BPF プログラムは IHL フィールドを読んで L4 フィールドのオフセットを動的に計算すること。固定 20 バイトオフセットを仮定すると、IP オプションが付いたパケットで誤ったフィールドを書き換える。
- **PSID 検証**: ingress で `R == 0` または `(psid_port >> (16-a-k)) & ((1<<k)-1) != psid` の場合はスルー（自 CE 宛外ポートは BR フィルタが担当）
- **nftables ICMP masquerade の動作前提**: `masquerade to :range` が ICMP Echo Identifier に作用する（`nf_nat_proto_icmp` が `NF_NAT_RANGE_PROTO_SPECIFIED` を尊重する）ことは統合テストで先行確認すること。カーネル・nftables バージョンによっては動作しない可能性がある。動作しない場合は ICMP Echo の Identifier を BPF 側で直接 staging range 内の値に書き換える処理（nftables に依存しない Identifier 割り当て）を別途検討する。ただし BPF 側で identifier を確定させるには conntrack との協調が必要になるため、初期実装のスコープ外とし動作確認結果を受けて判断する。
- **BPF ロード失敗時**: カーネルが古い・`CAP_BPF` 未付与等で `EbpfManager::load()` が失敗した場合はデーモン起動をハードエラーとして終了する。複数 R-block が必要な用途では eBPF は必須コンポーネントであり、nftables のみでの縮退動作はサポートしない。
- **clsact qdisc の残留**: Aya の TC リンク drop は filter を削除するが clsact qdisc 自体は残る。`link_tc()` は qdisc が既存の場合でも同じ interface に filter を追加できるため通常は問題ない。ただしデーモン異常終了後の再起動時には古いフィルタが残る可能性があるため、`link_tc()` の前に既存の mapecd フィルタを明示的に削除（または置換）する処理を入れること。
- **異常終了後の再起動時の staging ポート漏れ窓（既知制限）**: デーモンが異常終了すると、BPF filter は即座に消えるが nftables の staging range ルールは残存する。再起動後に `link_tc()` が完了するまでの短い窓で、masquerade により staging range に変換されたパケットが BPF 変換なしに WAN へ送出される（staging ポートのまま）。この窓は通常数十ミリ秒以内であり、PSID 準拠ポートではないためブロードバンドルータが破棄する可能性があるが、通信障害は再起動完了後に自然回復する。設計上許容するが、将来的に許容できない場合は BPF プログラムの pin (`/sys/fs/bpf/`) による永続化を検討する。
- **PSID 切り替え時のコネクション断**: `update_config()` で CONFIG_MAP を書き換えると、更新前に確立済みの TCP/UDP コネクションは古い staging↔psid マッピングで conntrack エントリを保持しているため強制切断される。PSID 変更はネットワーク再接続イベントに相当するレアケースであり、この挙動は設計上許容する。
- **CONFIG_MAP の非アトミック更新**: `BpfArray` は複数 CPU コアから並列アクセスされるが、更新操作はアトミックではない。`update_config()` 実行中に進行中のパケット処理が中途半端な状態の `PsidConfig` を読む可能性がある。ただし PSID 変更自体がレアケースであり、発生しても既存コネクションの強制切断（上記）の範囲内に収まるため設計上許容する。将来的に厳密なアトミック性が必要になった場合は `PinMap` + spinlock か二重バッファ方式への移行を検討する。
- **ICMP Error メッセージ（初期実装の既知制限）**: Destination Unreachable・Time Exceeded 等の ICMP エラーメッセージは内部に元のパケットヘッダ（埋め込みパケット）を含み、RFC 7597 ではこの埋め込みパケットのポート番号も変換対象とされる。しかし初期実装では ICMP Echo 以外の ICMP type はすべて TC_ACT_OK でスルーするため、ICMP エラーの embedded packet 内ポート番号は変換されない。ICMP エラーを含む通信で conntrack マッチが失敗することがあるが、初期実装のスコープ外とする。
- **受信 ICMP Echo Request（ingress type 8）のスコープ外**: ingress は ICMP Echo Reply（type 0）のみを変換対象とする。Internet 側から LAN ホスト宛の ICMP Echo Request（type 8）が PSID マップドポートに届いたケースは、MAP-E の NAT モデルでは BR フィルタが担当するため CE の BPF では変換しない（初期実装のスコープ外）。
