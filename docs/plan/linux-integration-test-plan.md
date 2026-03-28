# Linux 統合テスト実装計画

## 背景と目的

現在のユニットテスト（133件）はビジネスロジック層を広くカバーしているが、Linux カーネルとの実際のインターフェース部分は Mock 実装でのみ検証されている。以下の領域が実環境での動作を保証されていない：

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
| **Linux Network Namespace** | Netlink・AF_PACKET・sysctl・nft | `sudo` または `CAP_NET_ADMIN` が必要。`ip netns add` は `/var/run/netns/` への書き込みが必要なため root 必須。CI では `sudo cargo test` で対応 |
| **tempfile + inotify** | inotify リース監視 | 実ファイルシステムを使えば `ignored` テストを復活できる |
| **QEMU (KVM)** | フルスタック E2E | Namespace で困難な部分（実 DHCPv6 パケット受信など）のみ |

### 統合テストの配置

```
tests/
├── common/
│   ├── mod.rs              # pub mod netns; pub mod veth; を宣言
│   ├── netns.rs            # Network Namespace ヘルパー
│   └── veth.rs             # veth ペア作成ヘルパー
├── netlink_integration.rs      # Netlink トンネル/アドレス/ルート
├── nftables_integration.rs     # nft コマンド実行・バージョン互換性
├── inotify_integration.rs      # リースファイル監視
├── sysctl_integration.rs       # ip_forward / ipv6 forwarding
└── full_lifecycle_integration.rs # lifecycle::apply/update/cleanup E2E
```

各テストファイルは以下のガードを先頭に記述して Linux 以外では自動スキップ：

```rust
// non-Linux ではファイルごとコンパイル対象外にする
#![cfg(target_os = "linux")]
```

`#[cfg(target_os = "linux")] mod tests { ... }` のようにモジュールレベルで囲む方法でも機能するが、ファイルレベルのインナーアトリビュート `#![cfg(...)]` を使うことで `use` 文や共通関数を含むファイル全体が対象外になり、Linux 以外でのコンパイルエラーを確実に防げる。

---

## Phase 1: テスト用 Network Namespace ヘルパーの実装

**目標**: 他の統合テストが利用できる共通ヘルパーを `tests/common/` に用意する。

### 1-1. `tests/common/mod.rs`

各統合テストファイルから `mod common;` で読み込むためのエントリポイント。

```rust
pub mod netns;
pub mod veth;
```

### 1-2. `tests/common/netns.rs`

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
        F: AsyncFnOnce(rtnetlink::Handle) -> anyhow::Result<T>;

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
3. **元 Namespace の保存**: `run()` の先頭で `/proc/self/ns/net` を `open(O_RDONLY)` して元 Namespace の FD を保存する
4. `nix::sched::setns(fd, CloneFlags::CLONE_NEWNET)` で現スレッドを移動
5. `rtnetlink::new_connection()` で Namespace 内の Handle を取得
6. クロージャを実行
7. **元 Namespace への復元**: クロージャ終了後（正常・エラー問わず）、保存しておいた FD に対して再度 `setns` して元 Namespace に戻る

`new_connection()` は `(connection, handle, _)` の 3-tuple を返す。`connection` は `tokio::spawn(connection)` でバックグラウンドタスクとして起動する必要がある。`current_thread` フレーバーでは同一スレッドで協調実行されるため、`run()` の先頭で spawn し、戻り時に Handle を drop することで接続が閉じられる。

> **復元が必要な理由**: `--test-threads=1` でテストを順次実行する場合でも、複数テストは同一 OS スレッドを使い回す。`run()` を抜けた後にスレッドが元 Namespace に戻っていないと、後続テストが意図せずテスト用 Namespace 内で実行され、`ip netns del` 後は削除済み Namespace を参照し続ける。`run()` の末尾（正常・パニック時ともに）で元 Namespace へ復元することでテスト間の分離を保証する。

**パニック安全実装方針**: `run()` の実装ではクロージャを `await` する前にローカルの Drop-guard 構造体を作成し、`Drop::drop` 内で元 Namespace への `setns` を実行する。これにより非同期クロージャ内でパニックが発生した場合でも OS スレッドが元 Namespace に復元される。

```rust
struct NsRestoreGuard {
    orig_fd: OwnedFd,
}
impl Drop for NsRestoreGuard {
    fn drop(&mut self) {
        // パニック時も含め必ず元 Namespace に戻る
        let _ = nix::sched::setns(&self.orig_fd, nix::sched::CloneFlags::CLONE_NEWNET);
    }
}

// run() 内でクロージャを呼ぶ直前に guard を生成
let _guard = NsRestoreGuard { orig_fd };
// ... setns でテスト Namespace に移動 ...
let result = f(handle).await;  // パニックしても Drop が発火
result
```

`tokio::test` 環境では `#[tokio::test]` マクロが `std::panic::catch_unwind` を用いてテストパニックをキャッチするが、Drop-guard パターンにより `catch_unwind` に依存せず Namespace 復元が保証される。

**制約**: `setns(2)` はスレッド単位で有効なため、**`TestNetNs` を使うテスト**は `#[tokio::test(flavor = "current_thread")]` を必須とする。Network Namespace を使用しない Phase 4（inotify）のテストはこの制約に該当しない。

**複数ステップテストでの `run()` 利用**: `run()` はクロージャに `rtnetlink::Handle` を渡して Namespace 内で実行する設計のため、1 テスト内で apply → update → cleanup のように複数の Netlink 操作を連続実行する場合は、**1 つのクロージャ内に全ステップを記述**する。`run()` を抜けると Handle は drop されるため、ステップ間で Namespace を維持したまま Handle を使い回す必要がある Phase 6 系テストでは特に注意する。

### 1-3. `tests/common/veth.rs`

Namespace 内に veth ペアを作成する補助関数。**Phase 7（QEMU）の AF_PACKET テスト向けに用意する**ものであり、Phase 1–6 では使用しない。

> **なぜ Phase 1–6 では不要か**: Netlink テスト（Phase 2）は dummy インターフェースで十分、nftables（Phase 3）・sysctl（Phase 5）・ライフサイクル（Phase 6）は実 IF が不要か ip6tnl を自前作成するため。AF_PACKET による実際の Ethernet フレーム送受信は Network Namespace だけでは再現できず、QEMU（Phase 7）が必要になる。

```rust
pub async fn create_veth_pair(
    handle: &rtnetlink::Handle,
    name_a: &str,
    name_b: &str,
) -> anyhow::Result<(u32, u32)>;  // (ifindex_a, ifindex_b)

pub async fn set_link_up(handle: &rtnetlink::Handle, ifindex: u32) -> anyhow::Result<()>;

pub async fn add_ipv6_linklocal(handle: &rtnetlink::Handle, ifindex: u32) -> anyhow::Result<()>;
```

### 1-4. `Cargo.toml` への追加

以下のみ追加が必要（`tokio`・`anyhow`・`tempfile` は既存の `[dependencies]` / `[dev-dependencies]` に存在するため追加不要）。

`test-util` はテスト専用機能（時刻シミュレーション等）のため `[dev-dependencies]` に追記する。Cargo はフィーチャーをマージするため、ビルド時は `[dependencies]` の `full` に加えて `test-util` が有効になる。

```toml
[dev-dependencies]
# uuid: Namespace 名の一意生成（Linux 専用でないため [target.linux] ではなく共通 [dev-dependencies] に配置）
uuid = { version = "1", features = ["v4"] }
# tokio test-util: 時刻シミュレーション（既存 [dependencies] の "full" に追加される）
tokio = { version = "1", features = ["test-util"] }

[target.'cfg(target_os = "linux")'.dev-dependencies]
# nix sched: setns(2) / CloneFlags（既存 nix エントリに sched フィーチャーを追加）
nix = { version = "0.29", features = ["sched"] }
```

> **注意**: `[target.'cfg(target_os = "linux")'.dependencies]` 側の `nix` は `["net", "socket", "inotify", "user", "signal"]` のみ。`[target.'cfg(target_os = "linux")'.dev-dependencies]` で `sched` フィーチャーを追加すると Cargo がマージするため、テストビルド時に `nix::sched::setns` と `nix::sched::CloneFlags` が利用可能になる。

---

## Phase 2: Netlink 統合テスト

**目標**: `netlink/` の実装が実カーネルで動作することを検証する。

**ファイル**: `tests/netlink_integration.rs`

### 2-1. ip6tnl トンネル作成・削除テスト

```
テスト名: test_create_and_delete_ip6tnl_tunnel
```

1. Network Namespace を作成
2. `lo` を UP にする（`bring_up_lo()`）
3. `get_link_index("lo")` で `lo` の ifindex を取得し `lo_ifindex` に保存する
4. `create_ip6tnl("mapecd-test0", ::1, ::2, lo_ifindex, 1500)` を呼び出す
5. `get_link_index("mapecd-test0")` でトンネルが存在することを確認
6. `delete_link(ifindex)` を呼び出す
7. `get_link_index` が `Err` を返すことを確認
8. Namespace 削除（Drop）

> **リモートアドレス `::2` のルート不在について**: Linux カーネルは `ip6tnl` 作成（`RTM_NEWLINK`）時点ではリモートエンドポイントへの到達性を検証しない。ルートチェックはトンネル経由でパケットを転送する際に初めて行われるため、新規 Namespace 内に `::2` へのルートがなくても作成コマンドは `ESRCH` / `ENETUNREACH` を返さない。

**確認項目**:
- NLA エンコードがカーネル 5.x および 6.x 双方で受け入れられること
- トンネルの `ip link show` 出力に `ip6tnl` が含まれること（`ip` コマンド経由で副次確認）

### 2-2. IPv4/IPv6 アドレス付与・削除テスト

```
テスト名: test_add_del_ipv4_addr
         test_add_del_ipv6_addr
```

1. Namespace 内に dummy インターフェースを作成

   **実装注意**: `NetlinkHandle` トレイトには dummy IF 作成メソッドが存在しないため、`rtnetlink::Handle` を直接使用する：

   ```rust
   handle.link().add().dummy(name.to_string()).execute().await?;
   ```

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

   **実装注意**: 上記と同様に `rtnetlink::Handle` の `handle.link().add().dummy(...).execute().await?` を使用する。
2. `add_ipv4_default_route(oif1)` を呼び出す
3. `get_ipv4_default_routes()` が `[oif1]` を返すことを確認
4. `add_ipv4_default_route(oif2)` を呼び出す
   - `add_ipv4_default_route` は内部で既存ルートを全削除してから追加する実装（`route.rs` 参照）
   - `get_ipv4_default_routes()` が `[oif2]` のみを返すこと（oif1 が削除され oif2 だけになること）を確認
5. `del_ipv4_default_route_by_oif(oif2)` で削除し、`get_ipv4_default_routes()` が空リストを返すことを確認

---

## Phase 3: nftables 統合テスト

**目標**: `nft` コマンドが実際にルールを受け入れることを、nftables バージョンを問わず検証する。

**ファイル**: `tests/nftables_integration.rs`

**前提条件チェック**: テスト開始時に `nft --version` でバージョンを確認し、0.9.3 未満の場合はテストをスキップ。

### 3-1. ルールセット適用・削除テスト

```
テスト名: test_apply_and_delete_ruleset
```

1. Network Namespace を作成する

   **注意**: `apply_ruleset` はトンネルインターフェースの実在確認を行わない（ルール文字列生成 → `nft -f -` 実行のみ）。nftables もルール適用時に IF の実在を検証しない（遅延評価）。そのため ip6tnl トンネルの事前作成は不要。Namespace 作成直後に次のステップに進める。

2. `apply_ruleset(&NftExecutor, port_ranges, "mapecd-test0", br_addr)` を呼び出す
3. `nft list table ip mapecd` でテーブルが存在することを確認
4. `nft list set ip mapecd port_ranges` でポートセットを検証
5. `delete_tables(&NftExecutor)` を呼び出す
6. `nft list table ip mapecd` が失敗することを確認

**Namespace 継承について**: `#[tokio::test(flavor = "current_thread")]` を使用する（Phase 1-2 で必須と定めた通り）と、tokio ランタイムの OS スレッドは 1 本になる。この状態で `setns(CLONE_NEWNET)` を呼ぶと、**そのプロセスの唯一のスレッド**が切り替わるため、プロセスレベルで Namespace が変わる。その後に `Command::spawn()` で子プロセスを起動すると、fork された子は親プロセスの Namespace を継承する。

この結果、`apply_ruleset` の内部 `nft -f -` も、検証用 `nft list` も、どちらも同じテスト Namespace 内で実行される。したがって検証コマンドに **`nsenter` は不要**：

```rust
Command::new("nft")
    .args(["list", "table", "ip", "mapecd"])
    .output()?;
```

> **注意**: `nft -N <netns>` オプションは存在しないため使用しないこと。将来テストを `multi_thread` フレーバーに変更する場合は、`apply_ruleset` および検証コマンドの **両方** を `nsenter --net=/var/run/netns/<name>` でラップする必要がある（片方だけでは Namespace が混在し検証が無意味になる）。

### 3-2. MSS Clamp・マスカレードルール構文検証

```
テスト名: test_ruleset_syntax_valid
```

`nft -c -f -`（dry-run モード）でルールセット文字列を渡し、構文エラーがゼロであることを検証する。

**実行コンテキスト**: `nft -c` は構文チェックのみを目的とするため、Network Namespace 内のルールセット状態には依存しない。`TestNetNs` を作成する必要はなく、ホスト Namespace 上で `Command::new("nft").args(["-c", "-f", "-"])` を直接実行してよい。ただし `nft -c` もカーネルの netfilter サブシステムへの接続を試みるため、`CAP_NET_ADMIN` は必要。CI での `sudo cargo test` で他のテストと同様に実行できる。

### 3-3. ポート範囲フォーマット検証

```
テスト名: test_port_ranges_in_nft_set
```

v6plus 相当のポート範囲（240 個のポート、PSID=5, a=4, k=8）を生成し、nft に適用してカーネルが受け入れることを確認する。

---

## Phase 4: inotify 統合テスト

**目標**: `dhcpv6/lease_watcher.rs` の `run_lease_watcher` を `tempdir` 経由で実際に動作させる。

**背景**: `run_lease_watcher` に `lease_dir: &Path` パラメータを追加したことで、`tempdir` を渡す統合テストが可能になった。同等のテスト（`test_run_lease_watcher_integration` / `test_run_lease_watcher_moved_to`）は `lease_watcher.rs` 内にユニットテストとして既に存在する。

`tests/inotify_integration.rs` に別途テストを作成する理由: CI の統合テスト実行コマンド `sudo -E cargo test --test '*_integration'` は `tests/` 以下のバイナリのみを対象とする。`lease_watcher.rs` 内のユニットテストは `cargo test --lib` でしか実行されない。inotify テスト自体に `sudo` は不要だが、**テストランナーの分離**（Netlink・nftables などの root 必須テストと同一コマンドで実行可能にする）を目的として `tests/inotify_integration.rs` に配置する。これにより `cargo test --lib`（一般ユーザー、ビジネスロジック）と `sudo -E cargo test --test '*_integration'`（root、OS インターフェース）が明確に分離される。

> **重複テストのメンテナンスについて**: `lease_watcher.rs` 内の既存ユニットテストと実質的に同じ内容になるため、`run_lease_watcher` の API（引数・戻り値）が変更された場合は両方を更新する必要がある。このコストを許容しつつ「テストランナー分離」の恩恵を優先するという設計判断である。

**ファイル**: `tests/inotify_integration.rs`

### 4-1. リースファイル監視テスト（IN_CLOSE_WRITE）

```
テスト名: test_lease_watcher_detects_update
```

```rust
#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_lease_watcher_detects_update() {
    use std::time::Duration;
    use mapecd::dhcpv6::lease_watcher;
    use mapecd::dhcpv6::LeaseEvent;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    let dir = tempfile::tempdir().unwrap();
    // lo インターフェースの ifindex は Network Namespace 内でも常に 1
    let lease_file = dir.path().join("1");

    // 初期ファイル作成（X-DELEGATED-PREFIX なし）
    std::fs::write(&lease_file, "ADDRESS=192.168.1.1\n").unwrap();

    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(4);

    let dir_path = dir.path().to_path_buf();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        lease_watcher::run_lease_watcher("lo", &dir_path, tx, cancel_clone).await
    });

    // ファイル更新（X-DELEGATED-PREFIX を追加）
    tokio::time::sleep(Duration::from_millis(50)).await;
    std::fs::write(
        &lease_file,
        "ADDRESS=192.168.1.1\nX-DELEGATED-PREFIX=2001:db8::/48\n",
    ).unwrap();

    // イベント受信を待機（最大 2 秒）
    let result = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(result.is_ok(), "inotify event not received within 2s");
    let LeaseEvent(prefix) = result.unwrap().unwrap();
    assert_eq!(prefix.prefix_len(), 48);

    cancel.cancel();
    handle.await.unwrap().unwrap();
}
```

> **`lo` を使う理由**: このテストはホスト Namespace 上で動作する（`TestNetNs` は使用しない）。ホスト上で `lo` の ifindex は常に `1` のため、インターフェース名と ifindex の対応が固定。テストの再現性を確保できる。なお、Phase 2-1 の Netlink テストでは `get_link_index("lo")` を呼んで動的に ifindex を取得しているが、inotify テストでは ifindex をリースファイル名（`"1"`）にのみ使用しており Netlink API を介さない。値が常に `1` であることが保証されているため、ここでは決め打ちで問題ない。

### 4-2. IN_MOVED_TO イベントテスト

`systemd-networkd` はリースファイルを tmpfile → rename（`IN_MOVED_TO`）で更新する。rename 経由のイベント検知を確認する。

```
テスト名: test_lease_watcher_moved_to
```

```rust
// atomic write で rename をシミュレート（IN_MOVED_TO を発生させる）
let tmp = dir.path().join(".tmp_lease");
std::fs::write(
    &tmp,
    "ADDRESS=192.168.1.1\nX-DELEGATED-PREFIX=2001:db8:1::/56\n",
).unwrap();
std::fs::rename(&tmp, &lease_file).unwrap();
```

---

## Phase 5: sysctl 統合テスト

**目標**: `daemon/lifecycle.rs` の sysctl 読み書きが実 `/proc/sys/` で動作することを確認する。

**ファイル**: `tests/sysctl_integration.rs`

**`run()` の利用方法**: sysctl の読み書きは `std::fs::read_to_string` / `std::fs::write` であり `rtnetlink::Handle` を使わない。`TestNetNs::run()` のクロージャは Handle を受け取るが `_handle` として無視してよい。`run()` の本質は `setns` で Namespace に移動することにあるため、sysctl テストでも同じ API で利用できる。Handle 不要なユースケース向けに独立した `enter()` API は追加しない（`run()` に統一することで Namespace ライフサイクルの管理を1箇所に集約する）。

```rust
ns.run(|_handle| async move {
    let val = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
    // ...
}).await?;
```

> **`/proc/sys/net/` のパス解決について**: `setns(CLONE_NEWNET)` は Network Namespace のみを切り替える（Mount Namespace は変わらない）。したがって `/proc/sys/net/` のパス自体はホストの Mount Namespace のものを参照している。ただし、Linux カーネルは `/proc/sys/net/` 以下の仮想ファイルを read/write する際にカレントスレッドの Network Namespace のパラメータを参照するため、`setns` 後に同じパスを書いてもホスト環境には影響しない。パス変更は不要。

### 5-1. ip_forward トグルテスト

**注意**: Network Namespace 内の sysctl は独立しているため、ホスト環境に影響しない。

```
テスト名: test_sysctl_ip_forward_in_netns
```

1. Network Namespace を作成
2. Namespace 内で `/proc/sys/net/ipv4/ip_forward` を読み、`trim_end()` した値を**初期値として変数に保存**する
3. `std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")` で `1` を書き込む
4. `std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")` で読み返し、`trim_end()` した結果が `"1"` であることを確認

   > **`trim_end()` を使う理由**: Linux カーネルは `/proc/sys/` の仮想ファイルを読み出す際に常に末尾 `\n` を付加する。`"1\n" == "1"` は偽になるため、比較前に両辺を `trim_end()` するか `contains("1")` でチェックすること。`lifecycle.rs` の `read_sysctl` 実装も `trim_end()` しているため、同じパターンに揃える。

5. 保存した初期値に戻す（`std::fs::write` で復元）
6. 再度 `read_to_string` して `trim_end()` した結果が保存した初期値と一致することを確認
7. Namespace 削除（Drop）

> **注意**: 新規 Network Namespace の `ip_forward` は通常 `0` だが、初期値をハードコードしない。`lifecycle::apply` も「`read_to_string` → 保存 → `write`」の順で実装されており（lifecycle.rs 参照）、テストも同パターンに揃えることで実装との整合性を保つ。なお `lifecycle.rs` 内の `read_sysctl` / `write_sysctl` は private 関数であるため、統合テストからは `std::fs::read_to_string` / `std::fs::write` を直接使用する。

> **テスト失敗時の復元保証**: テスト途中でパニックが発生した場合でも、`TestNetNs` の `Drop` によって Namespace ごと削除される。`/proc/sys/net/` 以下の sysctl 値は Network Namespace 固有のため、Namespace 削除と同時に消滅する。テスト内で明示的なロールバック処理（`defer` 相当）を追加しなくても、ホスト側の sysctl には一切影響しない。

**`/proc/sys/net/` 書き込みが Network Namespace に対して作用する理由**: `setns(CLONE_NEWNET)` で切り替えられた Network Namespace は、`/proc/sys/net/` 以下の値をカーネルが Network Namespace 単位で管理しているため。同一のファイルパスへの書き込みでも、実際に更新されるのはカレントスレッドの Network Namespace のパラメータであり、ホスト側 Namespace の値は変化しない。Mount Namespace の切り替えは不要。

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
2. `run()` クロージャ内で受け取った `rtnetlink::Handle` を `RtNetlinkHandle::new(handle)` でラップし、`NftExecutor` を生成する：

   ```rust
   ns.run(|handle| async move {
       // IPv6 アドレス確認用に raw handle のクローンを先に保存する
       // （RtNetlinkHandle::new() は handle を消費するため）
       let raw_handle = handle.clone();
       let mut nl = RtNetlinkHandle::new(handle);
       let nft = NftExecutor;
       // 以降のステップをこのクロージャ内で記述
   }).await?;
   ```

   > Phase 1-2 で定めた通り、apply → verify → update → cleanup の **全ステップを 1 クロージャ内に記述**する。`run()` を抜けると Handle が drop されるため、複数の `run()` 呼び出しに分割しない。

   > **`raw_handle` を別途保持する理由**: `RtNetlinkHandle::handle` フィールドは `pub(crate)` であり、`tests/` 配下の統合テストから直接アクセスできない。IPv6 アドレス確認（`handle.address().get().execute()`）のように `NetlinkHandle` トレイトに存在しない操作を行う際は、`run()` に渡された元の `rtnetlink::Handle`（`handle.clone()`）を直接使用する。`rtnetlink::Handle` は `Clone` を実装しているため、`RtNetlinkHandle::new()` に渡す前にクローンしておく。

3. `DaemonState::default()` と最小構成の `Config` を用意

   **`upstream_interface` の設定**: `lifecycle::apply` は `config.upstream_interface` に対して `get_link_index` を呼び CE IPv6 アドレスを付与する。テスト用 Network Namespace には `lo` しか存在しないため、`config.upstream_interface = "lo".to_string()` を設定する。

   ```rust
   let config = Config {
       upstream_interface: "lo".to_string(),
       tunnel_interface: "mapecd0".to_string(),
       tunnel_mtu: Some(1460),  // lo の MTU (65536) を使うと 65496 がトンネル MTU になりテストの再現性が下がるため明示指定
       pid_file: std::path::PathBuf::from("/tmp/mapecd-test.pid"),
       map_rules_cache_file: std::path::PathBuf::from("/tmp/mapecd-test-rules.cache"),
       duid_file: std::path::PathBuf::from("/tmp/mapecd-test-duid"),
       dhcpv6_mode: mapecd::config::DhcpV6Mode::Capture,
       use_v6plus_static_rules: false,
   };
   ```

   > **`Config::default()` が存在しない理由**: `Config` は `#[derive(Debug, Clone, Deserialize)]` のみであり `Default` を実装していない。`..Config::default()` は使えないため、全フィールドを明示的に指定する。`#[serde(default)]` フィールド（`tunnel_mtu`・`dhcpv6_mode`・`use_v6plus_static_rules`）は Deserialize 時のデフォルトが定義されているが、コード上の初期化とは別物であることに注意。`pid_file`・`map_rules_cache_file`・`duid_file` はテスト用の一時パスを指定し、実環境のファイルを誤って上書きしないようにする。

   > **`tunnel_mtu: None` を避ける理由**: `tunnel_mtu: None` にすると `apply_step3_create_tunnel` 内で `get_link_mtu("lo")` を呼び、`lo` の MTU（65536）から 40 を引いた 65496 がトンネル MTU として使われる。65496 はカーネルに受け入れられる値だが、実際の eth0 使用時（MTU 1460 → トンネル MTU 1420）とかけ離れており、テストの実環境再現性が下がる。`Some(1460)` を明示することで実際の使用シナリオに近い値を検証できる。

4. v6plus 相当の `MapeParams` を用意（PSID=5, a=4, k=8）
5. `lifecycle::apply(&mut state, &config, &params, &mut nl, &nft)` を呼び出す
6. 以下を Netlink で確認:
   - `mapecd0` トンネルが存在する（`nl.get_link_index("mapecd0")` が `Ok` を返す）
   - トンネルに CE IPv6 アドレスが付いている（`raw_handle.address().get().execute()` でフィルタして確認）
   - IPv4 デフォルトルートが `mapecd0` 向きになっている（`nl.get_ipv4_default_routes()` が `mapecd0` の ifindex を含む）
   - CE IPv4 アドレス（`params.ipv4/32`）がトンネルに付与されている（`raw_handle.address().get().execute()` で AF_INET アドレスをフィルタして確認）
7. 以下を nft コマンドで確認（Phase 3-1 と同様に `Command::new("nft")` で実行）:
   - `nft list table ip mapecd` が成功する（exit code 0）
   - `nft list set ip mapecd port_ranges` の出力に期待するポート範囲が含まれる

### 6-2. update テスト（差分更新）

```
テスト名: test_lifecycle_update_ce_ipv6_in_netns
         test_lifecycle_update_port_ranges_in_netns
```

`lifecycle::update()` には `ce_ipv6 / br_address / ipv4 / port_ranges のみ` の4分岐があり、それぞれで再作成範囲が異なる。最低限、以下の2ケースを検証する：

**test_lifecycle_update_ce_ipv6_in_netns**（トンネル再作成を伴う最大変化）:

1. `apply` 後、CE IPv6 アドレスが変わった `MapeParams` を用意
2. `lifecycle::update(&mut state, &config, &old, &new, &mut nl, &nft)` を呼び出す
3. 旧 CE IPv6 アドレスが削除され、新アドレスが付与されることを確認：

   ```rust
   // update 後のアドレス一覧を取得して新旧を確認
   let addrs: Vec<_> = raw_handle
       .address()
       .get()
       .execute()
       .try_collect()
       .await?;
   // 旧アドレスが存在しないこと
   let old_found = addrs.iter().any(|msg| {
       msg.attributes.iter().any(|a| matches!(a, AddressAttribute::Address(IpAddr::V6(a)) if *a == old.ce_ipv6))
   });
   assert!(!old_found, "old CE IPv6 should have been removed");
   // 新アドレスが存在すること
   let new_found = addrs.iter().any(|msg| {
       msg.attributes.iter().any(|a| matches!(a, AddressAttribute::Address(IpAddr::V6(a)) if *a == new.ce_ipv6))
   });
   assert!(new_found, "new CE IPv6 should be present");
   ```

**test_lifecycle_update_port_ranges_in_netns**（Step 6 のみ再適用の最小変化）:

1. `apply` 後、ポート範囲のみが変わった `MapeParams` を用意（`ce_ipv6` / `br_address` / `ipv4` は同一）
2. `lifecycle::update(&mut state, &config, &old, &new, &mut nl, &nft)` を呼び出す
3. `nft list set ip mapecd port_ranges` の出力が新しいポート範囲に更新されていることを確認

### 6-3. cleanup テスト

```
テスト名: test_lifecycle_cleanup_in_netns
```

1. `apply` 後、cleanup 前に sysctl の期待値をローカル変数に保存する（`lifecycle::cleanup` は `state.original_ip_forward.take()` を呼ぶため cleanup 後は `None` になる）：

   ```rust
   let expected_ip_forward = state.original_ip_forward.clone().unwrap_or_default();
   let expected_ipv6_forward = state.original_ipv6_forward.clone().unwrap_or_default();
   ```

2. `lifecycle::cleanup(&mut state, &config, &params, &mut nl, &nft)` を呼び出す

   > **`cleanup` の戻り値**: `lifecycle::cleanup` は `()` を返す（`Result` ではない）。内部エラーはすべて `warn!` で続行する設計のため、呼び出し元は `.await` するだけでよい（`?` は不要）。

3. トンネルが削除されていることを確認（`nl.get_link_index("mapecd0")` が `Err` を返す）
4. nft テーブルが削除されていることを確認（`Command::new("nft").args(["list", "table", "ip", "mapecd"])` が非ゼロ終了）
5. sysctl が元の値に復元されていることを確認：
   - `std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap().trim_end()` が `expected_ip_forward` と一致すること
   - `std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding").unwrap().trim_end()` が `expected_ipv6_forward` と一致すること

   > **`trim_end()` が必要な理由**: Linux カーネルは `/proc/sys/` の read に常に末尾 `\n` を付加する（例: `"0\n"`）が、`read_sysctl()` の `trim_end()` により `state.original_*` は `"0"` として格納されている。`expected_*` も同様に trim 済みのため、read 結果のみ `trim_end()` すれば比較が成立する。

---

## Phase 7: QEMU による E2E テスト（オプション）

Network Namespace で再現が困難な以下のシナリオは QEMU で対応する。

> **背景との対応**: 「背景と目的」で挙げた未保証領域のうち **AF_PACKET ソケット**（実 IF でのパケット受信・BPF フィルタ）は、Network Namespace 内では実際の Ethernet フレーム送受信を再現できないため、本 Phase で対応する。Phase 1–6 には意図的に含めていない。

### 対象シナリオ

| シナリオ | 理由 |
|---|---|
| AF_PACKET パッシブキャプチャ | 実際の Ethernet フレームと DHCPv6 パケット送受信が必要 |
| フルデーモン起動・終了 | PID ファイル管理、systemd 連携 |
| 複数インターフェースを使った MAP-E 通信 | カーネルの転送処理を含む |

### 7-1. QEMU 環境セットアップ（CI 向け）

`ubuntu-latest` ランナーでは 2023年以降 `/dev/kvm` が利用可能になっているが、組織ポリシーや runner 世代によっては使えない場合がある。利用可能かどうかを事前チェックし、存在しない場合は TCG（ソフトウェアエミュレーション）にフォールバックする。

```yaml
# .github/workflows/e2e-test.yml
- name: Install QEMU
  run: sudo apt-get install -y qemu-system-x86 qemu-utils cloud-image-utils

- name: Check KVM availability
  run: |
    if [ -e /dev/kvm ]; then
      echo "KVM_OPTS=-enable-kvm -cpu host" >> "$GITHUB_ENV"
    else
      echo "KVM_OPTS=-cpu qemu64" >> "$GITHUB_ENV"
    fi

- name: Cache Ubuntu cloud image
  id: cache-cloudimg
  uses: actions/cache@v4
  with:
    path: ubuntu-24.04-minimal-cloudimg-amd64.img
    key: ubuntu-noble-minimal-cloudimg-20240423  # イメージ更新時はキーを手動更新

- name: Download Ubuntu minimal cloud image
  if: steps.cache-cloudimg.outputs.cache-hit != 'true'
  run: |
    wget -q https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64.img

- name: Build test image
  run: make -f Makefile.e2e build-image

- name: Run E2E tests
  run: make -f Makefile.e2e test
  timeout-minutes: 10
```

> **キャッシュキーの管理**: `actions/cache` のキーにイメージのリリース日またはハッシュを含め、イメージ更新時はキーを変更して再取得する。毎回 250MB 超のダウンロードを行うと CI 時間の増大と外部ネットワーク障害リスクが生じるためキャッシュは必須。

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

**`Makefile.e2e` に必要なターゲット**:

| ターゲット | 内容 |
|---|---|
| `build-image` | cloud-init seed.img を生成し、mapecd バイナリを Ubuntu cloudimg に組み込んだ qcow2 を作成する |
| `test` | QEMU VM を起動し、`tests/e2e_test.sh` を SSH 越しに実行して終了コードで合否判定する |
| `clean` | 生成した qcow2 / seed.img を削除する |

### 7-3. AF_PACKET キャプチャ E2E テスト

1. QEMU VM 内に仮想 IF を作成
2. DHCPv6 サーバー（`dnsmasq`）を起動し、MAP-E Option（Option 94）を返すよう設定
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
      run: sudo -E cargo test --test '*_integration' -- --nocapture --test-threads=1
      env:
        RUST_LOG: debug
        CARGO_HOME: ${{ env.HOME }}/.cargo
```

> **注意**: `sudo -E` で `HOME` と `CARGO_HOME` を引き継ぐことで、事前にビルドされた依存クレートのキャッシュが再利用される。`CARGO_HOME` を明示することで root の `$HOME` と一般ユーザーのキャッシュディレクトリが混在するパーミッション問題を回避できる。

**権限要件**:

| テスト | 必要な権限 |
|---|---|
| Netlink 統合テスト | `CAP_NET_ADMIN`（または `sudo`） |
| nftables 統合テスト | `CAP_NET_ADMIN`（nft コマンド実行） |
| AF_PACKET テスト（Phase 7 QEMU E2E） | `CAP_NET_RAW` + `CAP_NET_ADMIN` |
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
| Phase 4 | inotify 統合テスト（`tests/` への配置） | 中 | なし（独立） |
| Phase 5 | sysctl 統合テスト | 中 | Phase 1 |
| Phase 6 | フルライフサイクル統合テスト | 高 | Phase 2, 3, 5 |
| Phase 7 | QEMU E2E テスト（AF_PACKET 含む） | 低 | Phase 1–6 完了後 |

---

## 既知の制限と回避策

| 制限 | 回避策 |
|---|---|
| `setns` はスレッド単位のため `tokio::spawn` と競合 | `#[tokio::test(flavor = "current_thread")]` を必須とし、Namespace 移動後に別スレッドが生成されないようにする |
| `setns` 後にテストが終了してもスレッドが Namespace に残る | `TestNetNs::run()` の末尾（正常・エラー問わず）で `/proc/self/ns/net` FD を使って元 Namespace に復元する（Phase 1-2 参照） |
| nft はカーネルの netfilter を操作するため Namespace 内でも `CAP_NET_ADMIN` が必要 | CI では `sudo cargo test` を使用 |
| ip6tnl 作成は同一 Namespace 内でも `CAP_NET_ADMIN` が必要 | 同上 |
| QEMU の KVM が CI 環境に存在しない場合がある | `/dev/kvm` の存在確認でチェックし、存在しない場合は TCG モードでフォールバック。TCG は低速なため、CI ジョブ全体のタイムアウトを `timeout-minutes: 10` に設定している（ジョブレベルの制限であり、テスト 1 件あたりの制限ではない点に注意） |
| Network Namespace の `ip netns add` は `/var/run/netns/` への書き込みを必要とする | CI では `sudo cargo test` を使用。`unshare --net` は user namespace 組み合わせで代替可能だが、Netlink 操作には `CAP_NET_ADMIN` が引き続き必要 |
