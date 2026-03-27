# v6プラス向け静的 MAP ルール内蔵 実装計画

## 背景と課題

`mapecd` は DHCPv6 Option 94（S46 MAP-E）から MAP ルールを取得する前提で設計されているが、v6プラスでは MAP ルール配信が行われないため、そのままでは `pending_map_rules` が揃わず MAP-E 設定が適用できない。

`https://ipv4.web.fc2.com/map-e.html` に組み込まれている JSの 3 テーブル（`ruleprefix31` / `ruleprefix38` / `ruleprefix38_20`）を Rust 側の静的データに変換し、IA_PD のみで計算を完結できる経路を追加する。`docs/v6plus-maprule.md` はルールの人間可読リファレンスおよびゴールデンテスト値の検証用として参照するが、正規データ源は JS ファイルとする。

## 方針（概要）

- **データ源**: 3 テーブル（`ruleprefix31` / `ruleprefix38` / `ruleprefix38_20`）を正規データ源とし、生成スクリプトで `MapRule` 配列を生成する。JS ファイルが更新された場合は生成スクリプトを再実行して生成物を更新する。
- **CE IPv6 アドレス形式の事前確認**: `v6plus-maprule.js` の計算ロジック（`rfc = false` の非 RFC 形式）と既存 `build_ce_ipv6`（RFC 7597 準拠）の差異を実機ないし仕様で確認し、実装前に修正要否を決定する。確認が完了するまで `build_ce_ipv6` に依存するゴールデンテストの CE IPv6 期待値は確定しない。
- 既存の `MapRule` / `compute_mape_params` を再利用し、特別な計算器を増やさず「静的ルール供給源」を追加する形で統合する。
- 既存の DHCPv6 取得・キャッシュ機構は維持し、設定で静的 v6プラスルール利用を有効化した場合に優先利用する。
- 既存の `apply_if_ready` 更新判定不備（`old_params` と `new_params` の比較が成立しない問題）を先に修正し、静的ルール導入後も差分更新が正しく機能するようにする。

## 実装スコープ

### 1) ルールデータの正規化と保持形式の設計

#### JS テーブルの構造と `MapRule` への変換

JS の 3 テーブルは各ルールの「IPv6 プレフィックス上位ビット → IPv4 プレフィックス上位バイト」の逆引き表である。各テーブルから `MapRule` フィールドを次のように導出する。

**共通パラメータ（テーブルごと固定）**:

| テーブル          | `ipv6_prefix_len` | `ea_length` | `psid_length` | `psid_offset` | `ipv4_prefix_len` |
| ----------------- | ----------------- | ----------- | ------------- | ------------- | ----------------- |
| `ruleprefix38`    | 38                | 18          | 8             | 4             | 22                |
| `ruleprefix31`    | 31                | 25          | 8             | 4             | 15                |
| `ruleprefix38_20` | 38                | 18          | 6             | 6             | 20                |

`ea_length = 56 - ipv6_prefix_len`、`ipv4_prefix_len = 32 - (ea_length - psid_length)` の式で導出できることを生成時に検証する。

**キーから IPv6 プレフィックスの復元**:

- `ruleprefix31` キー K31（32 ビット整数）:
  - `hextet[0] = K31 >> 16`
  - `hextet[1] = K31 & 0xfffe`（bit0 は可変のため 0）
  - IPv6 プレフィックス = `hextet[0]:hextet[1]::/31`
- `ruleprefix38` / `ruleprefix38_20` キー K38（最大 40 ビット整数）:
  - `hextet[0] = K38 >> 24`
  - `hextet[1] = (K38 >> 8) & 0xffff`
  - `hextet[2] = (K38 & 0xff) << 8`（下位 10 ビット相当: bit[8-9] は可変のため 0）
  - IPv6 プレフィックス = `hextet[0]:hextet[1]:hextet[2]::/38`

**テーブル値からの IPv4 プレフィックス復元**:

各テーブル値 `v = [a, b, ...]` の可変ビットを 0 でマスクし、`Ipv4Net` を構築する。

- `ruleprefix38` 値 `[a, b, c]`:
  - `ipv4_prefix = Ipv4Net::new(Ipv4Addr::new(a, b, c & 0xFC, 0), 22)`
  - （下位 2 ビットが CE プレフィックスからの可変ビット: `(hextet[2] & 0x0300) >> 8`）
- `ruleprefix31` 値 `[a, b]`:
  - `ipv4_prefix = Ipv4Net::new(Ipv4Addr::new(a, b & 0xFE, 0, 0), 15)`
  - （bit0 が CE プレフィックスからの可変ビット: `hextet[1] & 0x0001`）
- `ruleprefix38_20` 値 `[a, b, c]`:
  - `ipv4_prefix = Ipv4Net::new(Ipv4Addr::new(a, b, c & 0xF0, 0), 20)`
  - （下位 4 ビットが CE プレフィックスからの可変ビット: `(hextet[2] & 0x03c0) >> 6`）

**BR アドレスの決定**:

各キーから prefix31 値を求め、JS の `peeraddr` 決定ロジックを生成器側で再現する。

prefix31 の計算（全テーブル共通）:

- `ruleprefix31` キー K31: `prefix31 = K31`
- `ruleprefix38` / `ruleprefix38_20` キー K38: `prefix31 = (K38 >> 24) * 0x10000 + ((K38 >> 8) & 0xfffe)`

BR アドレス決定規則（優先順位順）:

| 条件                                                                                   | BR アドレス                                                                                                             |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `0x24047a80 <= prefix31 < 0x24047a84`                                                  | `2001:260:700:1::1:275`                                                                                                 |
| `0x24047a84 <= prefix31 < 0x24047a88`                                                  | `2001:260:700:1::1:276`                                                                                                 |
| `(0x240b0010 <= prefix31 < 0x240b0014)` または `(0x240b0250 <= prefix31 < 0x240b0254)` | `2404:9200:225:100::64`                                                                                                 |
| 上記条件1-3 に該当しない `ruleprefix38_20` テーブルのエントリ                          | `2001:380:a120::9`                                                                                                      |
| 上記いずれにも該当しない（`ruleprefix38` の大半、JS では `peeraddr = false`）          | `2001:380:a120::9`（デフォルト補完: JS では BR 未定義だが、実サーバーデータ `docs/v6plus-maprule.md` に基づき補完する） |

この優先順位は JS ソース（行807-816）の分岐順序を忠実に再現したものである。`ruleprefix38_20` のエントリでも prefix31 が条件1-3 の範囲と重なる場合は異なる BR が割り当てられる点に注意する（生成スクリプト実行時に実際の重なりの有無を確認し、重なりがあれば個別に対処する）。

BR アドレス決定は**生成器側で完結**させ、Rust 実行時は再計算しない（生成済み `MapRule.br_address` をそのまま使用するデータ駆動方式）。

`is_fmr` は全エントリ `true` 固定（v6プラス全ルール FMR）。

#### CE IPv6 アドレス形式の事前確認（実装前必須）

`docs/v6plus-maprule.js`（行 773-778）は「非 RFC モード」（`rfc = false`）で CE アドレスを構築する:

```
hextet[4] = octet[0]                    → bits 64-79: IPv4 第1オクテット
hextet[5] = (octet[1] << 8) | octet[2] → bits 80-95: IPv4 第2・3オクテット
hextet[6] = octet[3] << 8              → bits 96-111: IPv4 第4オクテット
hextet[7] = psid << 8                  → bits 112-127: PSID
```

既存 `build_ce_ipv6`（`src/map/calc.rs:86`）は RFC 7597 Section 5.2 準拠で bits 80-111 に IPv4 を配置する。両者は異なる CE IPv6 アドレスを生成する。

- 実装前に実機確認またはプロトコル仕様照合により、v6プラス（OCN）が使用する CE アドレス形式を確定する。
- 非 RFC 形式が必要な場合は `build_ce_ipv6` に v6プラス用変種を追加するか既存関数を拡張し、変更をタスクリストに加える。
- RFC 7597 形式で正しいことが確認できた場合は既存の `build_ce_ipv6` をそのまま使用し、その旨をコードコメントで明記する。
- ゴールデンテストの CE IPv6 期待値はこの確認後に確定する。

#### 保持形式と妥当性検証

- 実行時は順序付き `Vec<MapRule>` を唯一の保持形式とし、`HashMap` 等の非順序構造を選択ロジックに使わない（決定性担保）。
- 生成時およびロード時にルール妥当性を検証し、少なくとも以下を満たさない場合は起動失敗とする:
  - `psid_offset + psid_length <= 16`（`calc_port_ranges` のシフト破綻防止）
  - `ea_length >= psid_length`
  - `ipv6_prefix_len + ea_length <= 64`（`IA_PD` との整合）
  - `ea_length == 56 - ipv6_prefix_len`（導出値の一致確認）
- v6プラス静的ルール集合が空（0 件）になった場合は起動失敗とする（fail-fast）。
- 既存 `compute_mape_params` の前提（`ce_prefix.prefix_len() == ipv6_prefix_len + ea_length`）を満たすため、v6プラス静的ルール経路では CE prefix 長 `/56` 前提を仕様として明記する。
- `/56` 以外の IA_PD を受信した場合は設定不整合として `error` ログを出力し、デーモンは継続稼働して後続イベントで再評価する（panic/即時終了しない）。このとき **既存の `pending_ia_pd` は上書きしない**（チェックを `state.pending_ia_pd = Some(prefix)` より前に置き、不正なプレフィックスで旧値を汚染しない）。既存トンネルが稼働中であればそのまま維持し、次の有効な `/56` IA_PD 受信まで現状のトンネルを保持し続ける（即時 cleanup しない）。

### 2) 生成フロー（データ管理の再現性確保）

- 手書き転記は避け、`docs/v6plus-maprule.js` から Rust 定数を生成するワンショットスクリプト（開発用）を用意する。
- 生成物は `src/map/v6plus_rules.rs`（例）にコミットし、実行時に JS ファイルを読まない構成にする。
- 生成物には「生成元ファイル名」「生成元ファイル（`docs/v6plus-maprule.js`）の SHA256 ハッシュ」「総件数（`pub const RULE_COUNT: usize = N;`）」をコメントおよび定数で明示し、追跡可能にする（日時・git コミットハッシュは差分ノイズまたは git 管理状態依存になるため持たない。SHA256 ハッシュは `hashlib.sha256` 等でファイル内容から計算し、git の管理状態（dirty/clean）に依存しない形で取得する）。
- 生成結果の追従漏れ検知として、再生成結果との差分チェック（テストまたは CI 手順）を用意する。
- 生成器の出力順はテーブル優先順（`ruleprefix38` → `ruleprefix31` → `ruleprefix38_20`）と各テーブル内のキー昇順（数値昇順）で固定し、再生成時の非決定差分を防ぐ。
- **保持形式は `pub static V6PLUS_MAP_RULES: &[MapRule]`（スライス参照）とし、`pub const RULE_COUNT: usize = N;` を別途生成する**。`const` 配列にすると各使用箇所にコピーが発生するため `static` が適切。生成コードの具体的な形式は次の通りとする:
  ```rust
  static RULES: [MapRule; N] = [
      MapRule {
          ipv6_prefix: Ipv6Net::new_assert(Ipv6Addr::new(...), 38),
          ipv4_prefix: Ipv4Net::new_assert(Ipv4Addr::new(...), 22),
          ...
      },
      ...
  ];
  pub static V6PLUS_MAP_RULES: &[MapRule] = &RULES;
  pub const RULE_COUNT: usize = N;
  const _: () = assert!(V6PLUS_MAP_RULES.len() == RULE_COUNT);
  ```
  `Ipv4Net::new()`/`Ipv6Net::new()` は `Result` を返すため `const` コンテキストで使えない。`ipnet` 2.12.0 が提供する **`const fn new_assert()`** を使うこと（`const fn` であり `const`/`static` 初期化子として直接記述可能）。`const fn` であることはタスク 1 の事前確認で担保する。
- `RULE_COUNT` と `V6PLUS_MAP_RULES.len()` の一致はコンパイル時に検証することを優先する（上記の `const _: () = assert!(...)` を生成物に含める）。コンパイル時検証が困難な構造になった場合のみ、実行時 `anyhow::ensure` でのフォールバックを検討する。
- 起動時 fail-fast 条件として「静的ルール集合が 0 件でない」ことをあわせて `start_linux` 初期化フェーズで確認し、不一致・0件の場合は起動失敗とする。
- 上記 fail-fast 検証は `start_linux` の初期化フェーズで `startup_cleanup` より前に実施し、設定不整合時に既存ネットワーク状態を変更しない順序を保証する。なお、PID ファイル作成は `start` 関数内（`start_linux` 呼び出し前）に行われる。`PidGuard::Drop` は `std::fs::remove_file` を呼ぶ実装が確認済みであり、fail-fast 失敗時の PID ファイル自動削除は既に対処されている。
- **生成スクリプトのパース方法**:
  - 入力は `docs/v6plus-maprule.js`。Python の `eval()` では JS の数値リテラルを含むオブジェクトを安全にパースできないため、正規表現でキー・値を個別抽出する。
  - テーブル抽出: `var ruleprefix\d+\w*\s*=\s*\{([^}]+)\}` でテーブル本体を取得。`[^}]+` はデフォルトで改行を含む（`re.DOTALL` 不要）が、`re.DOTALL` フラグを明示的に付けることで意図を明確にしてもよい。
  - エントリ抽出: `(0x[0-9a-fA-F]+)\s*:\s*\[([^\]]+)\]` でキーと値配列を取得。
  - キーは Python の `int(key, 16)` で整数変換。値は `[int(v) for v in values.split(',')]` でリスト化。
  - **BR アドレスの補完**: 条件1-3 の特殊 prefix31 範囲に該当しない `ruleprefix38_20` エントリには `2001:380:a120::9` を割り当てる。条件1-3 にも `ruleprefix38_20` にも該当しない `ruleprefix38` エントリ（JS では `peeraddr = false`）には `2001:380:a120::9` を強制補完する。生成スクリプト実行時に `ruleprefix38_20` のエントリが条件1-3 の prefix31 範囲と重なるケースが存在しないことをアサートし、重なりがあった場合は処理を停止して手動対処を促す。
- 生成運用を手順化する:
  - 生成スクリプト配置: `tools/gen_v6plus_rules.py`（例）
  - 実行コマンド: `python tools/gen_v6plus_rules.py --input docs/v6plus-maprule.js --output src/map/v6plus_rules.rs`
  - 更新手順: `https://ipv4.web.fc2.com/map-e.html` のソースを保存して `docs/v6plus-maprule.js` を更新し、生成スクリプトを再実行する。
  - 検証コマンド: 再生成後に差分が無いことを `cargo test` 内の検証テストで確認（差分が出たら失敗）
  - CI では「生成スクリプト実行 → git diff --exit-code 相当の無差分確認」を必須化する。
  - CI が未整備のリポジトリでは、同等の無差分確認コマンドをローカル必須手順として `README`/開発手順に明記する。

### 3) 設定と起動経路への統合

- `Config` に v6プラス静的ルール利用フラグ（例: `use_v6plus_static_rules`）を追加。
- `use_v6plus_static_rules` のデフォルト値は `false` とし、未指定時は既存動作（キャッシュ優先 + DHCPv6 更新）を維持する。環境変数上書きキー（例: `MAPECD_USE_V6PLUS_STATIC_RULES`）も仕様化する。環境変数対応は既存の `Config::load` で使用しているライブラリ（figment 等）の標準的な上書き機構に従って実装する。既存フィールドに環境変数対応がなければ本フィールドも実装しないものとし、その旨を設定ドキュメントに明記する。
- `daemon/runner.rs` 起動時の `pending_map_rules` 初期化優先順位を次の順にする:
  1. v6プラス静的ルール（有効時）
  2. キャッシュ
  3. DHCPv6 受信待ち
- 起動時に「静的ルール有効化状態」「採用したルール供給源（静的/キャッシュ/DHCPv6待ち）」を `info` ログで明示し、運用時に判別可能にする。
- 静的ルール有効時はキャッシュ読込（`load_rules_cache`）自体をスキップし、起動時から静的ルール集合のみを `pending_map_rules` に設定する。
- 静的ルール有効時の既存キャッシュファイルは「読まない・書かない」を原則とし、ファイル自体は削除せず保持する（無効化時のロールバック容易性を優先）。
- 現行実装コード（`src/config.rs`）には `map_rules` / `map_rule` の実装がないため、本計画では明示的静的設定は導入対象外とする（必要なら別タスクで追加）。一方で `README.md` / `docs/config-format.md` には旧仕様記述が残っているため、本タスク内で実装実態に合わせて修正する。
- DHCPv6 `Both` 受信時、静的ルール有効なら `handle_both` で MAP ルール更新とキャッシュ保存をスキップし、`pending_ia_pd` 更新と `apply_if_ready` のみを実行する（`IaPdReceived` / `LeaseEvent` と同等の挙動に揃える）。
- 静的ルール有効時は、DHCPv6 受信ルールの**キャッシュ保存も行わない**（静的/動的混在による次回起動時の汚染防止）。
- DHCPv6 `IaPdReceived` および `lease_watcher` (`LeaseEvent`) 経路でも、ルール集合は固定（静的または起動時選択結果）で IA_PD のみ更新することを明記する。
- 静的ルール有効時に `NoPrefixMatch` が発生しても DHCPv6 ルールへフォールバックせず、静的ルール集合の問題として扱うことを仕様化する。`NoPrefixMatch` 発生時に既存トンネルが稼働中（`tunnel_ifindex.is_some()`）であっても、即時 cleanup はせず既存トンネルを保持して後続の有効な IA_PD 受信まで待機する（同挙動は `/56` 以外 IA_PD 受信時と同様の「旧状態保持・後続再評価」方針による）。
- `NoPrefixMatch` のログレベル:
  - 静的ルール有効時: `error`（運用上の設定不整合として扱う）
  - 静的ルール無効時（DHCPv6 由来ルール使用時）: 現行通り `warn` を維持する
  - デーモンはいずれの場合も継続稼働し、後続 IA_PD 受信で再評価可能な状態を維持する（即時終了はしない）。

### 4) モジュール配線と既存不具合修正

- `src/map/v6plus_rules.rs` を `src/map/mod.rs` から公開し、`runner` から参照可能にする。
- `/56` 前提チェックは `apply_if_ready` / `try_compute` の副作用経路に委ねず、`handle_ia_pd`（および同等の IA_PD 入口）で **`state.pending_ia_pd = Some(prefix)` を実行する前に**事前に実施する。静的ルール有効時の `handle_both` も `ia_pd` パラメータに対して同じ `/56` 事前チェックを適用すること（`handle_both` は現行コードで `state.pending_ia_pd = Some(ia_pd)` を直接セットしており、`handle_ia_pd` を経由しないため）。`/56` 以外は `error` ログを出してそのイベント処理を打ち切り、`state.pending_ia_pd` を更新せず（旧値を保持し）、`NoPrefixMatch` へ誤変換させない。
- `runner` の更新判定で「変更前 `params`」と「再計算後 `params`」を正しく比較できるよう、`apply_if_ready` で `try_compute()` 実行**前**に `old_params = state.params.clone()` を退避し、`try_compute()` 後の `new_params = state.params.clone()` と比較するように修正する。

  修正後の `apply_if_ready` の判定フロー:
  1. `old_params = state.params.clone()` を退避（`try_compute()` 前）
  2. `state.try_compute()` を実行（`state.params` が更新される）
  3. `new_params = state.params.clone()` を取得
  4. `state.tunnel_ifindex.is_some()` で apply/update を分岐:
     - `is_none()` → 初回 `lifecycle::apply`
     - `is_some()` → `has_changed(old_params, &new_params)` が `true` のときのみ `lifecycle::update`
  5. `old_params` が `None` かつ `tunnel_ifindex.is_some()` の場合（前回 apply 後に params がリセットされた異常状態）は `error` ログを出して `lifecycle::cleanup` → `lifecycle::apply` を再試行する。このとき cleanup に渡す `params` は `new_params`（再計算済みの値）を使用する。cleanup は旧アドレスの特定を要するステップ（例: `lifecycle::cleanup` 内の `params.ce_ipv6` を使った旧 CE IPv6 /128 の削除）も含むが、`old_params` が消失している以上 `new_params` で代替するほかなく、旧アドレスが残留するリスクを `error` ログで可視化する。なお、`startup_cleanup` が起動時に残留した nftables テーブル・トンネル・ルートをクリアするため、通常の起動後運用中にこの異常状態が発生することは想定しにくい。

- 上記修正により、静的ルール導入時/未導入時のどちらでも `lifecycle::has_changed` の分岐が正しく動作することをテストで固定する。
- テスト容易性のため、`runner` の分岐ロジック（静的優先判定・`Both` 受信時の MAP ルール更新可否）を副作用の薄い `pub(crate)` ヘルパーへ抽出し、`#[cfg(test)]` で Linux 依存を最小化して検証できる形にする。`#[cfg(target_os = "linux")]` 関数から呼び出す純粋ヘルパー層を設け、OS 非依存テストを可能にする。

### 5) ルール選択ロジックの整合確認

- `DaemonState::try_compute` の「先頭一致ルールを採用」挙動を維持。
- テーブル優先順（`ruleprefix38` → `ruleprefix31` → `ruleprefix38_20`）と各テーブル内キー昇順を生成順として固定する（JS の分岐優先順に準拠）。
- 同一 `ipv6_prefix` が複数候補になる場合の決定規則（生成順優先）を仕様化し、非決定性を排除する。
- 既存 `compute_mape_params` が前提とする prefix/EA/PSID 制約を満たすことをロード時に検証する。

### 6) テスト計画

- 単体テスト:
  - 3 テーブルの代表エントリがキー・値から期待通り `MapRule` に変換されること（IPv6 プレフィックス・IPv4 プレフィックス・`psid_length`・`ipv4_prefix_len` の導出を含む）。
  - `psid_length` 導出式（`ea_length - (32 - ipv4_prefix_len)`）の検証。
  - IPv4 プレフィックスのネットワークアドレス部が正しくマスクされること（`ruleprefix38` → `& 0xFC`、`ruleprefix31` → `& 0xFE`、`ruleprefix38_20` → `& 0xF0`）。
  - `psid_offset + psid_length <= 16` など制約違反データを拒否すること。
  - `ruleprefix38_20` 相当の `psid_offset=6, psid_length=6`（`a+k=12`）パラメータで `calc_port_ranges` が正しいポート範囲を返すこと（他テーブルの `a=4, k=8` と異なる組み合わせのため個別に検証する）。
  - BR アドレスの分岐境界（prefix31 範囲境界、`ruleprefix38_20` 条件、デフォルト `2001:380:a120::9`）を固定値で検証すること。
  - `ruleprefix38` → `ruleprefix31` → `ruleprefix38_20` の優先順が実装で維持されること。
  - 静的ルール有効時に `runner` がキャッシュ・DHCPv6 ルールで上書きしないこと。
  - 静的ルール有効時に DHCPv6 `Both` を受けてもキャッシュ保存しないこと。
  - 静的ルール有効時に DHCPv6 `Both` を受けた場合、`pending_map_rules` が不変で `pending_ia_pd` のみ更新されること。
  - IA_PD が `/56` 以外のとき、`handle_ia_pd` 相当ロジックで `error` 扱いとなり、`try_compute` を呼ばずに処理スキップされること。
  - 上記 2 件を `handle_both` 直テストではなく、抽出した `pub(crate)` ヘルパー単位で検証できること（OS 依存と I/O 依存を分離）。
  - `apply_if_ready` が修正後に「`try_compute()` 前の旧値 vs 新値」を正しく比較し、`update` / no-op を正しく分岐できること。特に「旧値 == 新値」の場合に `lifecycle::update` を呼ばないことを確認する。
  - `tunnel_ifindex.is_some()` かつ `old_params` が `None` の異常ケースで `error` ログ出力とクリーンアップが行われること。
  - 重複または重なりうるルール候補がある場合、`Vec` 先頭一致（生成順優先）で決定されること。
  - 静的ルール無効時の `NoPrefixMatch` が `warn` ログになること。
  - 静的ルール有効時の `NoPrefixMatch` が `error` ログになること。
- 起動時検証テスト:
  - 静的ルール生成物の `RULE_COUNT` 定数と実際の `Vec<MapRule>` の `len()` が一致しない場合に fail-fast で起動失敗すること。
  - fail-fast 検証（0件・件数不一致・致命的ロード不整合）が `start_linux` 初期化段階で実行され、イベントループ開始前に停止すること。
  - fail-fast 失敗時に PID ファイルが残留しないこと（`PidGuard` の Drop またはエラーパス）。
- 回帰テスト:
  - 静的ルール無効時は現行動作（キャッシュ優先 + DHCPv6 更新）が維持されること。
  - `IaPdReceived` / `LeaseEvent` 経由で IA_PD 更新時に既存ルールで再計算されること。
- 参照整合テスト（ゴールデン）:
  - いくつかの入力プレフィックスについて、Rust 実装の `MapeParams`（IPv4/PSID/ポート範囲）が期待値と一致すること。期待値は `docs/v6plus-maprule.js` の計算ロジックを手動で実行して求めた値を fixture に記録する。
  - **CE IPv6 アドレスの期待値は、CE 形式（RFC 7597 か非 RFC か）の確認後に fixture に追加する**。確認前はポート範囲・IPv4・PSID のみをゴールデン対象とする。
  - 最低限、3 テーブル（`ruleprefix38` / `ruleprefix31` / `ruleprefix38_20`）の代表値、BR アドレス分岐境界、`NoPrefixMatch` ケースを含めること。
  - テスト再現性確保のため、ゴールデン期待値はリポジトリ内 fixture（静的 JSON/TOML 等）に固定し、テスト実行時に `docs/v6plus-maprule.js` を直接読みに行かない。

## 実装タスク（順序付き）

1. **CE IPv6 アドレス形式の確認**（実装前必須・ブロッカー）: v6プラスが使用する CE IPv6 形式が RFC 7597 か非 RFC（JS の `rfc=false` 形式）かを実機ないし仕様で確定する。非 RFC 形式の場合は `build_ce_ipv6` の修正タスクをここに挿入し、`compute_mape_params` / `MapeParams` のドキュメントコメント（現在 "RFC 7597 Section 5.2 に従い導出" と記載）の更新もあわせて実施する。あわせて `ipnet` 2.12.0 の `Ipv6Net::new_assert()` / `Ipv4Net::new_assert()` が `const fn` であることを ipnet のソース/ドキュメントで確認し、`static RULES: [MapRule; N]` 初期化子での利用可能性を担保する。
2. `runner::apply_if_ready` の `old_params` を `try_compute()` 前に退避するよう修正（既存不具合の先行修正）。合わせて `tunnel_ifindex.is_some()` との判定統合を仕様通りに整理する。
3. `docs/v6plus-maprule.js` 解析スクリプト作成（開発用、`tools/gen_v6plus_rules.py`）。あわせて `Cargo.toml` の `ipnet` 依存を `version = "2"` から `version = "2.12"` に更新し、`new_assert` の利用に必要な最小バージョンを明示する。
4. `src/map/v6plus_rules.rs` 生成・追加（`RULE_COUNT` 定数を含む）
5. `src/map/mod.rs` へモジュール公開を追加
6. `src/config.rs` に静的ルール利用設定（`use_v6plus_static_rules: bool`）追加 + バリデーション（環境変数対応は既存機構の確認後に決定）。既存フィールドのパターンに合わせ `#[serde(default)]` を付与して後方互換性を確保する。
7. `src/daemon/runner.rs` の初期化優先順位更新（静的 > キャッシュ > DHCPv6）
8. 静的ルール有効時のキャッシュ読込スキップ（起動時）を実装
9. DHCPv6 `Both` 処理に静的優先ガード適用
10. DHCPv6 `Both` のキャッシュ保存抑止（静的有効時）を実装
11. `runner` の静的優先判定/`Both` 更新ロジックを `pub(crate)` ヘルパーへ抽出（テスト可能化）
12. IA_PD `/56` 事前チェックを `handle_ia_pd` および静的ルール有効時の `handle_both` 内 IA_PD 処理の入口に実装し、`InvalidCePrefix` の `NoPrefixMatch` 化を防止（`handle_both` は `handle_ia_pd` を経由せず `state.pending_ia_pd` を直接セットするため、両方の入口にチェックが必要）
13. `NoPrefixMatch` のログレベルを静的ルール有効/無効で分岐するよう変更
14. `IaPdReceived` / `LeaseEvent` 経路の期待動作をテストで固定（/56 以外スキップ含む）
15. 単体テスト・回帰テスト・ゴールデンテスト追加（CE IPv6 形式確認後に期待値を確定）
16. 再生成差分チェック手順（テストまたは CI）を追加し、CI がある場合はジョブに組み込む（CI 未整備の場合はローカル必須手順として文書化）
17. `docs/config-format.md` と `README.md` を現行実装に全面整合（旧 `map_rule` 記述だけでなく、実在しない/未実装キーやネスト差異、`dhcpv6_mode` などトップレベル/セクション構造の差分も是正）し、新設定項目と優先順位を追記
18. `docs/` 直下に存在する旧計画文書（`docs/v6plus-static-map-rules-plan.md`・`docs/static-map-rules.md`）、`docs/plan/v6plus-static-map-rules-plan.md`（本ファイル、実装完了後）、および `static-map-rules-review.txt` を整理する（削除またはアーカイブ化し、リポジトリルートに不要なレビューメモを残さない）

## 注意点・リスク

- **CE IPv6 アドレス形式の不一致リスク（高）**: `v6plus-maprule.js` は非 RFC 形式（bits 64-111 に IPv4）、既存 `build_ce_ipv6` は RFC 7597 形式（bits 80-111 に IPv4）で、生成する CE アドレスが異なる。v6プラス BR が期待する形式と一致しない場合、MAP-E トンネルが正常に機能しない。タスク 1 でブロッカーとして先行確認すること。
- **`ruleprefix38` の BR アドレス未定義（JS の `peeraddr = false`）**: JS の BR 決定ロジックは `ruleprefix38` エントリの大半に対して BR アドレスを割り当てない（`peeraddr = false`）。本計画ではデフォルト値 `2001:380:a120::9` を使用するが、この値は `docs/v6plus-maprule.md` の実サーバーデータに基づいており、将来 OCN がルール構成を変更した場合に再検証が必要。
- **`docs/v6plus-maprule.js` 更新時の追従リスク**: `https://ipv4.web.fc2.com/map-e.html` 側のデータが更新された場合、`docs/v6plus-maprule.js` の手動更新と生成スクリプトの再実行が必要。更新手順を `README`/開発手順に明記する。
- **ルール件数が多くバイナリサイズが増える可能性**: 生成物の保持形式を `static &[MapRule]` とすることでコピーは発生しないが、バイナリへのデータ埋め込みサイズは実測で確認する。圧縮表現が必要な場合は別途検討する。
- **ルール優先順・重複解決規則の非決定性リスク**: テーブル優先順（`ruleprefix38` → `ruleprefix31` → `ruleprefix38_20`）とキー昇順を固定しないと、再生成時に選択結果が変わるリスクがある。
- **fail-fast と PID ファイル残留**: `PidGuard::Drop` が `std::fs::remove_file` を呼ぶ実装は確認済みであり、fail-fast 失敗時の PID ファイル自動削除は対処済み。

- **`lifecycle::has_changed` が `rule` フィールドを比較から除外している点（静的ルール利用への影響なし）**: `has_changed` は `ce_ipv6` / `ipv4` / `psid` / `br_address` / `port_ranges` のみを比較し、`MapeParams.rule` は比較対象外となっている。静的ルール有効時はルール集合が不変のため影響を受けないが、DHCPv6 `Both` 経路でルール自体が変更された場合に `has_changed` が `false` を返して `update` がトリガーされない可能性がある。この挙動は本計画の対象外（既存設計）だが、回帰テスト追加時に静的ルール無効パスの動作確認で踏む可能性があるため注意する。

## 完了条件

- v6プラス環境で DHCPv6 Option 94 が無くても、IA_PD 受信のみで `MapeParams` が確定し `apply_if_ready` が動作する。
- 既存環境（Option 94 提供あり）で挙動退行がない。
- v6プラス静的ルール有効時に `/56` 以外の IA_PD を受信した場合、`error` ログで不整合を可視化しつつデーモン継続・再評価可能な挙動が確認できる。
- CE IPv6 アドレス形式が実機または仕様で確認済みであり、ゴールデンテストの期待値に反映されている。
- ルール更新手順（`docs/v6plus-maprule.js` 更新 → 生成スクリプト再実行 → 生成物コミット）がドキュメント化され、再生成可能である。
- `apply_if_ready` の `old_params` 退避修正後、パラメータ変化なし時に `lifecycle::update` が呼ばれないことがテストで固定されている。
