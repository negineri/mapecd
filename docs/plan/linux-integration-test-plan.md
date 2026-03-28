# Linux 統合テスト実装計画

## 背景と目的

現在のユニットテスト（127件）はビジネスロジック層を広くカバーしているが、Linux カーネルとの実際のインターフェース部分は Mock 実装でのみ検証されている。以下の領域が実環境での動作を保証されていない：

| 未保証領域 | 問題 |
|---|---|
| Netlink 操作（tunnel/addr/route） | カーネルが NLA エンコードを受け入れるか未検証 |
| AF_PACKET ソケット | 実 IF でのパケット受信・BPF フィルタ未検証 |
| inotify リース監視 | イベント配信ロジックが `ignored` のまま |
| sysctl 書き込み | `/proc/sys/` への読み書きが実際に反映されるか未検証 |
| nft コマンド実行 | nftables バージョン互換性が未検証 |

本計画では **Linux Network Namespace** を主手段とし、一部 QEMU を補完的に使用することで、CI 環境（GitHub Actions）で実行可能な統合テスト基盤を構築する。

---

## アーキテクチャ方針

### 手段の選択

| 手段 | 対象 | 理由 |
|---|---|---|
| **Linux Network Namespace** | Netlink・AF_PACKET・sysctl・nft | `unshare(1)` または `ip netns` で権限なしに使用可能。CI に適している |
| **tempfile + inotify** | inotify リース監視 | 実ファイルシステムを使えば `ignored` テストを復活できる |
| **QEMU (KVM)** | フルスタック E2E | Namespace で困難な部分（実 DHCPv6 パケット受信など）のみ |

### 統合テストの配置

```
tests/
├── netlink_integration.rs      # Netlink トンネル/アドレス/ルート
├── nftables_integration.rs     # nft コマンド実行・バージョン互換性
├── inotify_integration.rs      # リースファイル監視
├── sysctl_integration.rs       # ip_forward / ipv6 forwarding
└── full_lifecycle_integration.rs # lifecycle::apply/update/cleanup E2E
```

各テストファイルは以下のガードを先頭に記述して Linux 以外では自動スキップ：

```rust
#[cfg(not(target_os = "linux"))]
fn main() {} // non-Linux は全スキップ

#[cfg(target_os = "linux")]
mod tests { ... }
```

---

## Phase 1: テスト用 Network Namespace ヘルパーの実装

**目標**: 他の統合テストが利用できる共通ヘルパーを `tests/common/` に用意する。

### 1-1. `tests/common/netns.rs`

Network Namespace の作成・削除・内部での Netlink Handle 取得をラップするヘルパー。

```rust
pub struct TestNetNs {
    name: String,
}

impl TestNetNs {
    /// 一意な名前の Network Namespace を作成（`ip netns add` 相当）
    pub fn create() -> anyhow::Result<Self>;

    /// この Namespace に入った tokio ランタイムで `f` を実行
    pub async fn run<F, T>(&self, f: F) -> anyhow::Result<T>
    where
        F: AsyncFn(rtnetlink::Handle) -> anyhow::Result<T>;

    /// lo インターフェースを UP にする（トンネル作成の前提条件）
    pub async fn bring_up_lo(&self) -> anyhow::Result<()>;
}

impl Drop for TestNetNs {
    fn drop(&mut self) {
        // `ip netns del <name>` で削除
    }
}
```

**実装方針**:

1. `ip netns add <uuid>` で Namespace 作成
2. `/var/run/netns/<uuid>` を `open(O_RDONLY)` で取得
3. `nix::sched::setns(fd, CloneFlags::CLONE_NEWNET)` で現スレッドを移動
4. `rtnetlink::new_connection()` で Namespace 内の Handle を取得

**制約**: `setns(2)` はスレッド単位で有効なため、テストは `#[tokio::test(flavor = "current_thread")]` を必須とする。

### 1-2. `tests/common/veth.rs`

Namespace 内に veth ペアを作成する補助関数。AF_PACKET テストで必要。

```rust
pub async fn create_veth_pair(
    handle: &rtnetlink::Handle,
    name_a: &str,
    name_b: &str,
) -> anyhow::Result<(u32, u32)>;  // (ifindex_a, ifindex_b)

pub async fn set_link_up(handle: &rtnetlink::Handle, ifindex: u32) -> anyhow::Result<()>;

pub async fn add_ipv6_linklocal(handle: &rtnetlink::Handle, ifindex: u32) -> anyhow::Result<()>;
```

### 1-3. `Cargo.toml` への追加

```toml
[dev-dependencies]
tokio = { version = "1", features = ["full", "test-util"] }
anyhow = "1"
tempfile = "3"
uuid = { version = "1", features = ["v4"] }
```

---

## Phase 2: Netlink 統合テスト

**目標**: `netlink/` の実装が実カーネルで動作することを検証する。

**ファイル**: `tests/netlink_integration.rs`

### 2-1. ip6tnl トンネル作成・削除テスト

```
テスト名: test_create_and_delete_ip6tnl_tunnel
```

1. Network Namespace を作成
2. `lo` を UP にする
3. `create_ip6tnl("mapecd-test0", ::1, ::2, lo_ifindex, 1500)` を呼び出す
4. `get_link_index("mapecd-test0")` でトンネルが存在することを確認
5. `delete_link(ifindex)` を呼び出す
6. `get_link_index` が `Err` を返すことを確認
7. Namespace 削除（Drop）

**確認項目**:
- NLA エンコードがカーネル 5.x および 6.x 双方で受け入れられること
- トンネルの `ip link show` 出力に `ip6tnl` が含まれること（`ip` コマンド経由で副次確認）

### 2-2. IPv4/IPv6 アドレス付与・削除テスト

```
テスト名: test_add_del_ipv4_addr
         test_add_del_ipv6_addr
```

1. Namespace 内に dummy インターフェースを作成
2. `add_ipv4_addr(ifindex, 192.0.2.1)` を呼び出す
3. RTM_GETADDR で 192.0.2.1/32 が存在することを確認
4. `del_ipv4_addr` でアドレスを削除
5. RTM_GETADDR でアドレスが消えたことを確認

### 2-3. IPv4 デフォルトルート操作テスト

```
テスト名: test_add_ipv4_default_route
         test_replace_ipv4_default_route
```

1. Namespace 内に dummy インターフェースを 2 つ作成（oif1, oif2）
2. `add_ipv4_default_route(oif1)` を呼び出す
3. `get_ipv4_default_routes()` が `[oif1]` を返すことを確認
4. `add_ipv4_default_route(oif2)` を呼び出す（oif1 が削除され oif2 に置き換わることを確認）
5. `del_ipv4_default_route_by_oif(oif2)` で削除

---

## Phase 3: nftables 統合テスト

**目標**: `nft` コマンドが実際にルールを受け入れることを、nftables バージョンを問わず検証する。

**ファイル**: `tests/nftables_integration.rs`

**前提条件チェック**: テスト開始時に `nft --version` でバージョンを確認し、0.9.3 未満の場合はテストをスキップ。

### 3-1. ルールセット適用・削除テスト

```
テスト名: test_apply_and_delete_ruleset
```

1. Network Namespace を作成し、`ip6tnl` トンネルを作成する
2. `apply_ruleset(NftExecutor, port_ranges, "mapecd-test0", br_addr)` を呼び出す
3. `nft list table ip mapecd` でテーブルが存在することを確認
4. `nft list set ip mapecd port_ranges` でポートセットを検証
5. `delete_tables(NftExecutor)` を呼び出す
6. `nft list table ip mapecd` が失敗することを確認

**注意**: nft はルートレス Namespace でも動作するが、Network Namespace 内で実行する必要がある。`std::process::Command` でサブプロセスを Namespace 内に入れるか、`nft -N <netns>` オプションを使用する。

### 3-2. MSS Clamp・マスカレードルール構文検証

```
テスト名: test_ruleset_syntax_valid
```

`nft -c -f -`（dry-run モード）でルールセット文字列を渡し、構文エラーがゼロであることを検証する。実際の適用は行わないためルートレス環境でも実行可能。

### 3-3. ポート範囲フォーマット検証

```
テスト名: test_port_ranges_in_nft_set
```

v6plus 相当のポート範囲（240 個のポート、PSID=5, a=4, k=8）を生成し、nft に適用してカーネルが受け入れることを確認する。

---

## Phase 4: inotify 統合テスト（`#[ignore]` 解除）

**目標**: `dhcpv6/lease_watcher.rs` の `test_run_lease_watcher_integration` を実際に動作させる。

**ファイル**: `tests/inotify_integration.rs`（または `lease_watcher.rs` 内の `#[ignore]` を除去）

### 4-1. リースファイル監視テスト

現在 `ignored` になっているテストを以下の方針で修正する：

```rust
#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_lease_watcher_detects_update() {
    let dir = tempfile::tempdir().unwrap();
    let lease_file = dir.path().join("1.lease");

    // 初期ファイル作成
    std::fs::write(&lease_file, "X-NTP-Servers=ntp.example.com\n").unwrap();

    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(4);

    let handle = tokio::spawn(run_lease_watcher(
        lease_file.clone(),
        cancel.clone(),
        tx,
    ));

    // ファイル更新
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(
        &lease_file,
        "X-NTP-Servers=ntp.example.com\nDELEGATED-IPv6-PREFIX=2400:4050:dead:1234::/56\n",
    ).unwrap();

    // イベント受信を待機（最大 2 秒）
    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(result.is_ok(), "inotify event not received within 2s");
    let prefix = result.unwrap().unwrap();
    assert_eq!(prefix.prefix_len(), 56);

    cancel.cancel();
    handle.await.unwrap().unwrap();
}
```

**修正方針**: `ignored` 属性を除去し、`#[cfg(target_os = "linux")]` で Linux 専用マークにする。inotify は Linux 実環境であれば tempdir で動作する（QEMU 不要）。

### 4-2. IN_MOVED_TO イベントテスト

`systemd-networkd` は `.lease` ファイルを tmpfile → rename（`IN_MOVED_TO`）で更新する。rename 経由のイベント検知を確認する。

```rust
// atomic write で rename をシミュレート
let tmp = dir.path().join(".tmp_lease");
std::fs::write(&tmp, content).unwrap();
std::fs::rename(&tmp, &lease_file).unwrap();
```

---

## Phase 5: sysctl 統合テスト

**目標**: `daemon/lifecycle.rs` の sysctl 読み書きが実 `/proc/sys/` で動作することを確認する。

**ファイル**: `tests/sysctl_integration.rs`

### 5-1. ip_forward トグルテスト

**注意**: Network Namespace 内の sysctl は独立しているため、ホスト環境に影響しない。

```
テスト名: test_sysctl_ip_forward_in_netns
```

1. Network Namespace を作成
2. Namespace 内で `/proc/sys/net/ipv4/ip_forward` を読む（初期値 `0` を確認）
3. `write_sysctl("/proc/sys/net/ipv4/ip_forward", "1")` を呼び出す
4. 読み返して `1` であることを確認
5. 元の値 `0` に戻す
6. Namespace 削除（Drop）

**実装上の注意**: `setns` で Namespace に移動後、`/proc/sys/` のパスは自動的に Namespace 内のものを参照するため、パス変更は不要。

### 5-2. IPv6 forwarding テスト

同様に `net/ipv6/conf/all/forwarding` を検証する。

---

## Phase 6: フルライフサイクル統合テスト

**目標**: `daemon/lifecycle.rs` の `apply → update → cleanup` が実 Netlink + 実 nft で動作することを確認する。

**ファイル**: `tests/full_lifecycle_integration.rs`

### 6-1. apply テスト

```
テスト名: test_lifecycle_apply_in_netns
```

1. Network Namespace を作成
2. `RtNetlinkHandle` と `NftExecutor` を生成
3. v6plus 相当の `MapeParams` を用意（PSID=5, a=4, k=8）
4. `lifecycle::apply(&params, &mut nl, &nft)` を呼び出す
5. 以下を Netlink で確認:
   - `mapecd0` トンネルが存在する
   - トンネルに CE IPv6 アドレスが付いている
   - IPv4 デフォルトルートが `mapecd0` 向きになっている
6. 以下を nft コマンドで確認:
   - `ip mapecd` テーブルが存在する
   - ポートセットに期待するポートが含まれる

### 6-2. update テスト（差分更新）

```
テスト名: test_lifecycle_update_ce_ipv6_in_netns
```

1. `apply` 後、CE IPv6 アドレスが変わった `MapeParams` を用意
2. `lifecycle::update(&old, &new, ...)` を呼び出す
3. 旧 CE IPv6 アドレスが削除され、新アドレスが付与されることを確認

### 6-3. cleanup テスト

```
テスト名: test_lifecycle_cleanup_in_netns
```

1. `apply` 後に `lifecycle::cleanup(&params, ...)` を呼び出す
2. トンネルが削除されていることを確認
3. nft テーブルが削除されていることを確認
4. sysctl が元の値に復元されていることを確認

---

## Phase 7: QEMU による E2E テスト（オプション）

Network Namespace で再現が困難な以下のシナリオは QEMU で対応する。

### 対象シナリオ

| シナリオ | 理由 |
|---|---|
| AF_PACKET パッシブキャプチャ | 実際の Ethernet フレームと DHCPv6 パケット送受信が必要 |
| フルデーモン起動・終了 | PID ファイル管理、systemd 連携 |
| 複数インターフェースを使った MAP-E 通信 | カーネルの転送処理を含む |

### 7-1. QEMU 環境セットアップ（CI 向け）

GitHub Actions の `ubuntu-latest` ランナーでは KVM が利用可能な場合がある。利用できない場合は TCG（ソフトウェアエミュレーション）にフォールバックする。

```yaml
# .github/workflows/e2e-test.yml
- name: Install QEMU
  run: sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils

- name: Download Ubuntu minimal cloud image
  run: |
    wget -q https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.img

- name: Build test image
  run: make -f Makefile.e2e build-image

- name: Run E2E tests
  run: make -f Makefile.e2e test
  timeout-minutes: 10
```

### 7-2. テストイメージ構成

```
e2e/
├── Makefile.e2e          # ビルド・実行手順
├── cloud-init/
│   ├── user-data         # mapecd インストール・設定
│   └── network-config    # 仮想 NIC 設定
├── scripts/
│   ├── setup-veth.sh     # QEMU 内 veth + DHCPv6 サーバー起動
│   └── verify.sh         # 期待する設定が適用されているか検証
└── tests/
    └── e2e_test.sh       # テスト実行スクリプト
```

### 7-3. AF_PACKET キャプチャ E2E テスト

1. QEMU VM 内に仮想 IF を作成
2. DHCPv6 サーバー（`dibbler-server` または `dnsmasq`）を起動し、MAP-E Option（Option 94）を返すよう設定
3. `mapecd start --mode capture --interface eth0` を起動
4. `verify.sh` で設定適用を確認

---

## CI 統合

### GitHub Actions 設定方針

```yaml
# .github/workflows/test.yml（既存に追加）
integration-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable

    - name: Install nftables
      run: sudo apt-get install -y nftables iproute2

    - name: Run integration tests (requires root for netns + nft)
      run: sudo -E cargo test --test '*_integration' -- --nocapture
      env:
        RUST_LOG: debug
```

**権限要件**:

| テスト | 必要な権限 |
|---|---|
| Netlink 統合テスト | `CAP_NET_ADMIN`（または `sudo`） |
| nftables 統合テスト | `CAP_NET_ADMIN`（nft コマンド実行） |
| AF_PACKET テスト | `CAP_NET_RAW` + `CAP_NET_ADMIN` |
| inotify テスト | 一般ユーザーで可 |
| sysctl テスト（netns 内） | `CAP_NET_ADMIN`（setns） |

GitHub Actions では `sudo cargo test` で解決できる。セルフホストランナーの場合は `CAP_NET_ADMIN` を付与する。

---

## 実装スケジュール

| Phase | 内容 | 優先度 | 依存 |
|---|---|---|---|
| Phase 1 | Network Namespace ヘルパー | 高 | なし |
| Phase 2 | Netlink 統合テスト | 高 | Phase 1 |
| Phase 3 | nftables 統合テスト | 高 | Phase 1 |
| Phase 4 | inotify `#[ignore]` 解除 | 中 | なし（独立） |
| Phase 5 | sysctl 統合テスト | 中 | Phase 1 |
| Phase 6 | フルライフサイクル統合テスト | 高 | Phase 2, 3, 5 |
| Phase 7 | QEMU E2E テスト | 低 | Phase 1–6 完了後 |

---

## 既知の制限と回避策

| 制限 | 回避策 |
|---|---|
| `setns` はスレッド単位のため `tokio::spawn` と競合 | `#[tokio::test(flavor = "current_thread")]` を必須とし、Namespace 移動後に別スレッドが生成されないようにする |
| nft はカーネルの netfilter を操作するため Namespace 内でも `CAP_NET_ADMIN` が必要 | CI では `sudo cargo test` を使用 |
| ip6tnl 作成は同一 Namespace 内でも `CAP_NET_ADMIN` が必要 | 同上 |
| QEMU の KVM が CI 環境に存在しない場合がある | `kvm_stat` でチェックし、存在しない場合は TCG モードでフォールバック。TCG は低速なため E2E テストは `--timeout 600s` に設定 |
| Network Namespace の `ip netns add` は `/var/run/netns/` への書き込みを必要とする | `unshare --net` 代替手段を検討。または `/var/run/netns/` は `CAP_NET_ADMIN` で書き込み可能 |
