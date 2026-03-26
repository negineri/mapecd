# mapecd 実装計画

## モジュール構成

```text
src/
├── main.rs                    # エントリポイント: CLI・ログ初期化・コマンドディスパッチ
├── cli.rs                     # clap CLI 定義 (start / status / stop / --config / --log-level)
├── config.rs                  # 設定読み込み・バリデーション
├── error.rs                   # 共通エラー型 (thiserror)
│
├── map/
│   ├── mod.rs
│   ├── rule.rs                # MapRule, PortParams, MapeParams 型定義
│   ├── calc.rs                # EA-bits / IPv4 / PSID / CE IPv6 計算
│   └── port_set.rs            # ポートセット計算 Port(R, j) 式
│
├── dhcpv6/
│   ├── mod.rs
│   ├── capture.rs             # AF_PACKET キャプチャモード [Linux only]
│   ├── client.rs              # 独立 DHCPv6 クライアントモード [Linux only]
│   ├── parser.rs              # OPTION_S46_CONT_MAPE パース（手書きバイトパーサー）
│   └── lease_watcher.rs       # inotify による /run/systemd/netif/leases/ 監視 [Linux only]
│
├── netlink/                   # [Linux only]
│   ├── mod.rs
│   ├── addr.rs                # RTM_NEWADDR / RTM_DELADDR（IPv6 /128 および IPv4）
│   ├── tunnel.rs              # RTM_NEWLINK / RTM_DELLINK (ip6tnl)
│   └── route.rs               # RTM_NEWROUTE / RTM_DELROUTE
│
├── nftables/
│   ├── mod.rs
│   └── manager.rs             # ルールセット生成・nft -f - 適用
│
└── daemon/
    ├── mod.rs
    ├── state.rs               # DaemonState (MapeParams スナップショット)
    ├── lifecycle.rs           # apply / update / cleanup
    └── runner.rs              # tokio select! イベントループ
```

## 実装フェーズ（TDD サイクル前提）

### Phase 1: 基盤整備

目標: `mapecd --help` が動く最小骨格。

| ステップ | 内容 |
| --- | --- |
| 1-1 | `error.rs` に `MapEError` 定義（thiserror）。定義すべき主要 variant: `ConfigNotFound { path: PathBuf }`, `InvalidConfig(String)`, `InvalidCePrefix`（EA-bits 長と CE prefix 長の不一致）, `NoPrefixMatch`（IA_PD にマッチする MAP Rule が `pending_map_rules` に存在しない場合。`try_compute` が `Err` を返す際に使用）, `MissingBrAddress`（`OPTION_S46_BR` が省略された場合）, `EmptyPortRanges`（`calc_port_ranges` の結果が空の場合の nftables 適用ガード）, `NetlinkError(String)`（Netlink 操作失敗）, `NftError(String)`（nft コマンド実行失敗） |
| 1-2 | `config.rs` の型定義と serde デシリアライズ（詳細は下記参照） |
| 1-3 | `cli.rs` の clap Derive 実装。`--config <PATH>`（デフォルト: `/etc/mapecd/config.toml`）と `--log-level <LEVEL>`（デフォルト: `info`）をグローバルオプションとして追加 |
| 1-4 | `main.rs` に tokio ランタイム + ロガー初期化（`tracing-subscriber`。`--log-level` 値を反映し、`/run/systemd/journal/socket` が存在する場合は `tracing-journald` を優先し、そうでない場合は stderr に出力） |

テスト: `config.rs` のフィールドごとにデシリアライズ単体テスト。デフォルト値・必須バリデーションの確認。

#### ステップ 1-2 詳細: `config.rs`（型定義・デシリアライズ・バリデーション）

設定ファイルの読み込みは `toml` crate を直接使用（`fs::read_to_string` + `toml::from_str`）。`config` crate は使用しない（TOML 単一ファイルで十分なため）。

**エラー処理:**

- 設定ファイルが存在しない場合（`io::ErrorKind::NotFound`）: `MapEError::ConfigNotFound { path: PathBuf }` を返し、`error!` ログを出力して終了コード 1 で即終了する

**デシリアライズ後バリデーション**（違反時はすべて `MapEError::InvalidConfig`）:

- `upstream_interface` / `tunnel_interface` が空文字列でなく、かつ 15 文字以内（IFNAMSIZ-1）であること
- 両フィールドが英数字・`-`・`_`・`.` のみで構成されていること（スペース・クォート・バックスラッシュ・セミコロン等は不許可。`generate_ruleset` での文字列インジェクションを設定読み込み段階で防ぐ）
- `upstream_interface` と `tunnel_interface` が異なる名前であること（WAN インターフェースと ip6tnl トンネルに同一インターフェースは使用不可）
- `tunnel_mtu` が `Some(v)` の場合、`v` が 1280 以上（IPv6 最小 MTU）かつ 65535 以下であること（0 や極小値を防ぐ。`v < 1280` の場合は `MapEError::InvalidConfig` を返す）

### Phase 2: MAP-E 純粋計算ロジック（優先度最高・Linux 不要）

目標: EA-bits 抽出からポートセット計算まで純粋関数として完成。macOS でも `cargo test --lib` が通る。

| ステップ | 内容 |
| --- | --- |
| 2-1 | `map/rule.rs` に `MapRule`, `PortParams`, `MapeParams` 型定義 |
| 2-2 | `map/calc.rs` に `extract_ea_bits`, `derive_ipv4_and_psid`, `build_ce_ipv6`, `compute_mape_params` 実装。`extract_ea_bits` は `ce_prefix.prefix_len() == rule.ipv6_prefix.prefix_len() + rule.ea_length` を検証し、不一致の場合は `MapEError::InvalidCePrefix` を返す。`ea_length == (32 - ipv4_prefix_len) + psid_length` の整合性検証（EA-bits の内部構成チェック）は本実装のスコープ外とする（DHCPv6 サーバーから受信したルール定義は正当と仮定し、CE prefix の整合性確認のみに留める）。`build_ce_ipv6` は RFC 7597 Section 5.2 に従い 128 ビットアドレスを構成する: `[Rule IPv6 prefix (r bits)] | [EA-bits (ea_length bits)] | [0-pad] | [IPv4 addr (32 bits, bits 80-111)] | [PSID << (16-k) (16 bits, bits 112-127)]`。下位 48 ビット（IPv4 addr + PSID）は `ea_bits` と `rule` から内部導出するため、呼び出し元が ipv4/psid を別途渡す必要はない |
| 2-3 | `map/port_set.rs` に `calc_port_ranges` 実装。各 R について `[Port(R, 0)..=Port(R, 2^a - 1)]` の範囲を算出した後、**隣接する `RangeInclusive` を結合するポストプロセス**（`end + 1 == next_start` を条件）を行い `Vec<RangeInclusive<u16>>` として返す（`a=0, k=0` のケースでは 65535 個のシングルポート範囲が `vec![1..=65535]` に正しく結合されることを確認すること） |

テスト: v6プラス固有値（a=4, k=8, PSID=5）でのポートセット計算（総数 240 ポートを検証）。`a=0`（除外ポートなし）のエッジケースで `Port(R, 0) = R * 2^k + PSID` となることを確認。CE IPv6 アドレス構成の RFC 7597 Section 5.2 準拠確認（`build_ce_ipv6` の下位 48 ビットに IPv4 アドレスと PSID が正しく配置されることを検証）。`extract_ea_bits` でプレフィックス長不一致（例: EA-bits 長 + rule IPv6 prefix 長 ≠ CE prefix 長）の場合に `MapEError::InvalidCePrefix` が返ることを確認。`a=0, k=0`（OPTION_S46_PORTPARAMS 省略デフォルト）の場合、`calc_port_ranges` は `vec![1..=65535]`（ポート 0 を除く全ポート）を返す（`k=0` のため PSID は 0 ビット幅 → PSID=0 が自明。`j` の範囲は [0, 2^0-1]={0}。`Port(R, 0) = R` となるため R∈[1, 65535] の各ポートが連続し、ポストプロセスの range 結合により `1..=65535` の単一レンジにまとめられる。この PSID=0 自明性と結合結果は `calc_port_ranges` 内のコメントで明示すること）。呼び出し元は `a=0, k=0` を特別扱いせずそのまま nftables の port_ranges セットに渡す。

### Phase 3: DHCPv6 パーサー（Linux 不要）

目標: `OPTION_S46_CONT_MAPE` を `MapRule` に変換するパーサーの完成。

注記: `dhcproto` crate は OPTION_S46_CONT_MAPE (94) / OPTION_S46_RULE (89) / OPTION_S46_BR (90) / OPTION_S46_PORTPARAMS (93) に対応していないため、手書きバイトパーサーとして実装する。`dhcproto` は DHCPv6 メッセージの外枠（Message-Type / Transaction-ID / Option TLV の走査）と IA_PD (OPTION_IA_PD=25) / IAPREFIX (OPTION_IAPREFIX=26) のパースに使用する。S46 オプションのペイロードは `parser.rs` で独自にパースする。

| ステップ | 内容 |
| --- | --- |
| 3-1 | `dhcpv6/parser.rs` に `parse_mape_container` 実装。`OPTION_S46_CONT_MAPE` 内の複数 `OPTION_S46_RULE` を `Vec<MapRule>` として返す。DHCPv6 Reply に複数の `OPTION_S46_CONT_MAPE` が存在する場合は最初に現れたもの（インデックス 0）のみを処理し、残りは無視する（実運用では複数コンテナは現れない想定）。`OPTION_S46_RULE` が 0 件の場合は空の `Vec<MapRule>` を返す（`try_compute` が `Ok(None)` を返して自然に吸収される） |
| 3-2 | OPTION_S46_RULE, OPTION_S46_BR, OPTION_S46_PORTPARAMS パース。`OPTION_S46_BR` は必須フィールドであり、省略された場合は `MapEError::MissingBrAddress` を返す（BR アドレスなしでは MAP-E 動作不可）。`OPTION_S46_PORTPARAMS` が省略された場合のデフォルト値: `psid_offset=0`（a=0）、`psid_length=0`（k=0）。この場合 PSID は EA-bits の全ビットを使用し、ポートセット制限なし（全ポートが使用可能）となる。`OPTION_S46_BR` が同一コンテナ内に複数存在する場合は最初に現れたものを採用し、残りは無視する（anycast 運用では同一 BR に解決されるため実用上問題ない） |
| 3-3 | `dhcproto` を用いた IA_PD パース関数を `parser.rs` に 2 種類追加する。**① `parse_ia_pd`**（capture モード用）: シグネチャは `fn parse_ia_pd(data: &[u8], iaid: Option<u32>) -> Option<Ipv6Net>` とする。戻り値は `Option<Ipv6Net>`（OPTION_IA_PD が存在しない・IAPREFIX が取得できない場合は `None`）。**② `parse_ia_pd_info`**（client モード用）: シグネチャは `fn parse_ia_pd_info(data: &[u8], iaid: Option<u32>) -> Option<IaPdInfo>` とする。`IaPdInfo` 構造体は `{ prefix: Ipv6Net, t1: u32, t2: u32, valid_lifetime: u32 }` とし（単位は秒）、IA_PD の `T1`/`T2` フィールドおよび IAPREFIX の `valid-lifetime` フィールドを含める（`preferred-lifetime` は本実装では使用しないが将来拡張のため無視してよい）。`T1=0` または `T2=0` の場合は RFC 3315 Section 22.4 に従い、それぞれ `valid_lifetime * 0.5`（T1）・`valid_lifetime * 0.8`（T2）を計算値として補完する（整数演算で端数切り捨て）。`valid_lifetime=0xFFFFFFFF`（無限大）の場合、T1/T2 の補完も `u32::MAX` とする。`parse_ia_pd_info` はプレフィックス抽出・複数 OPTION_IA_PD / IAPREFIX の選択ロジック・`OPTION_STATUS_CODE` の処理について `parse_ia_pd` と同一の仕様とする。両関数とも: `iaid` が `Some(v)` の場合は IAID が `v` と一致する OPTION_IA_PD を優先し、一致しない場合は先頭を採用（フォールバック）。`iaid` が `None` の場合は先頭を採用（capture モード）。client モードは `iaid = Some(ifindex)` で呼び出す。複数の IAPREFIX は先頭のみ採用。IA_PD サブオプションの Status Code が `Success`（0）以外のときは `None` を返す |

テスト: バイト列ハードコードのテストベクタでラウンドトリップ検証。複数ルールを含むコンテナのパーステスト。RFC 7598 フィールド境界値テスト。OPTION_S46_PORTPARAMS 省略時のデフォルト値適用テスト。複数 IAPREFIX を含む IA_PD で先頭のみ採用されることを確認。複数 OPTION_IA_PD を含む Reply で、IAID 一致時は対象 IA_PD が選択されること・不一致時は先頭が採用されること（`iaid = None` の場合も先頭採用）を確認。`parse_ia_pd_info` で T1/T2/valid_lifetime が正しく抽出されることを検証。T1=0 または T2=0 の場合に valid_lifetime からの補完計算が適用されること・`valid_lifetime=0xFFFFFFFF` の場合に T1/T2 も `u32::MAX` になることを確認。

### Phase 4: DHCPv6 受信（Linux・CAP_NET_RAW 依存）

目標: AF_PACKET キャプチャと独立クライアントの 2 モードを実装。

DHCPv6 Reply には IA_PD オプションと OPTION_S46_CONT_MAPE の両方が含まれる。各モードで MAP Rule と IA_PD の両方を同一パケットから取得し、`DaemonState` へ渡す。`lease_watcher`（Phase 5）は独立した IA_PD 更新源として使用し、systemd-networkd がリースを更新した際の再計算トリガーとして機能する。

注記: `client` モードは独立した DHCPv6 クライアントとして動作するため、systemd-networkd や NetworkManager が同一インターフェースで DHCPv6 を実行している場合は競合が発生する。`client` モードを使用する際は、事前に当該インターフェースの DHCPv6 管理を無効化すること。デフォルトは競合が発生しない `capture` モード。

注記（capture モード起動時遅延）: `capture` モードはパッシブに DHCPv6 Reply を待つため、デーモン単独再起動後は次の Renew（T1 タイマー後、最大 1800 秒程度）まで MAP Rule を取得できない。この期間中は MAP-E 設定が適用されない。対策として、MAP Rule 受信時に `config.map_rules_cache_file`（デフォルト: `/run/mapecd/rules.cache`）へ JSON 形式でシリアライズして保存し、起動時にキャッシュファイルが存在すれば `DaemonState.pending_map_rules` へ読み込む。`lease_watcher` が IA_PD を取得した時点でキャッシュ済み MAP Rule と組み合わせて即時設定を適用できる。`capture` モードではタイマー管理は不要で、捕捉した Reply パケットを契機にキャッシュを更新する。キャッシュもリースファイルも存在しない初回起動時は DHCPv6 交換を待つ必要があるが、`networkctl renew <upstream_interface>` を実行することで即時に Renew を強制できる。

#### ステップ 4-1: `dhcpv6/capture.rs`（AF_PACKET キャプチャ）

**AF_PACKET ソケット + BPF フィルタ設定**（socket2 + nix + libc）:

- ソケット作成後、`sockaddr_ll`（`libc::sockaddr_ll`）を構成して `bind` する。`sll_ifindex` に `nix::net::if_::if_nametoindex(upstream_interface)` で取得した ifindex を設定し、`sll_protocol` に `ETH_P_IPV6`（`0x86DD`、ビッグエンディアン）を設定する。bind することで対象インターフェースのパケットのみを受信し、他インターフェースのパケットを除外する
- BPF フィルタ条件: IPv6 かつ UDP dport 546（DHCPv6 クライアント宛）に限定
- `SO_ATTACH_FILTER` は nix 0.27 の高レベル API では非対応のため `libc::setsockopt` で `sock_fprog` 構造体を直接渡す
- BPF プログラムは Ethernet II フレームを前提（IPv6 次ヘッダフィールド offset=20、UDP dport offset=56）
- **VLAN 環境（802.1Q）はスコープ外**: オフセットが +4 バイトずれるため未対応（将来対応が必要な場合は VLAN 対応 BPF または `SOCK_RAW + ETH_P_ALL` での拡張が必要）
- DHCPv6 msg-type=7（Reply）の判定は BPF ではなくソフトウェア側で行う

**宛先 IPv6 アドレスフィルタリング**（他ホスト宛て Reply の誤処理防止）:

- `nix::ifaddrs::getifaddrs()` で `upstream_interface` の `AF_INET6` アドレスのうち `fe80::/10` に属するリンクローカルアドレスを取得する。この取得はパケット受信のたびに行うのではなく、**受信ループの冒頭で一度だけ実施し、変数に保持して使い回す**（`Option<Ipv6Addr>` として保持）。リンクローカルアドレスはインターフェースが UP している間は変化しないため、起動時一度の取得で十分
- 受信パケットの宛先アドレスが一致する場合のみ処理する
- リンクローカルアドレスが取得できない場合（インターフェース未 UP・RA 未受信等）は warn ログを出力してチェックをスキップ（起動直後の過渡状態への対処）。スキップした場合でも保持変数は `None` のままにし、**次のパケット受信時に再取得を試みる**（`Option::is_none()` を確認して再試行することで、RA 受信後に自動的にフィルタが有効になる）

**Reply の `OPTION_STATUS_CODE` 処理**:

- トップレベル Status Code が `Success`（0）以外 → warn ログを出力してそのパケットのイベント送出をスキップ
- IA_PD 内の Status Code は `parse_ia_pd`（Phase 3-3）が `None` を返すことで通知

**その他**:

- IA_PD を含まない Reply（例: Confirm への Reply）は `parse_ia_pd` が `None` を返すためイベント送出をスキップ
- `OPTION_S46_CONT_MAPE` がない Reply は `IaPdReceived` イベントを送出（既存の `pending_map_rules` を維持）
- T1/T2 タイマー管理は不要（パッシブスニッフィングのみ）

#### ステップ 4-2: `dhcpv6/client.rs`（独立 DHCPv6 クライアント）

**DUID 管理**:

- `config.duid_file`（デフォルト: `/var/lib/mapecd/duid`）から読み込み。存在しない場合は DUID-LLT を新規生成して永続化（`/run/` はリブートで消去されるため `/var/lib/` に配置）
- DUID-LLT の構成:
  - MAC アドレス: `nix::ifaddrs::getifaddrs()` で `upstream_interface` の `AF_PACKET` エントリから取得（存在しない場合は全ゼロ MAC + warn）
  - hardware-type = 1（Ethernet、IANA 規定）
  - `time` フィールド: RFC 8415 Section 11.2 の基準時刻（2000-01-01 00:00:00 UTC）からの経過秒数（u32）
- IAID（32 bit）: `nix::net::if_::if_nametoindex(upstream_interface)` で取得した ifindex を使用（失敗時は `0` + warn）

**Solicit → Advertise → Request → Reply サイクル**:

- Solicit: OPTION_CLIENTID + OPTION_IA_PD（IAID, T1=0, T2=0）+ **OPTION_ORO**（code=6、要求オプションコード: `OPTION_IA_PD`=25・`OPTION_S46_CONT_MAPE`=94）を含める。RFC 7598 Section 5 はクライアントが Solicit に OPTION_ORO を含め MAP オプション（94）を明示的に要求することを必須としている。Transaction ID は `rand::rng().random::<[u8; 3]>()` で生成
- Advertise 選択（RFC 3315 Section 17.1.2）:
  - SOL_TIMEOUT（1 秒）待機後、最初に到着した Advertise を採用
  - Preference=255 の Advertise を受信した場合は待機を打ち切り即採用
  - タイムアウト時は指数バックオフ（RT[n+1] = 2 × RT[n]、初回 RT = SOL_TIMEOUT=1 秒、上限 SOL_MAX_RT=120 秒）で Solicit を再送。各 RT に ±10% のジッタ（RFC 3315 Section 14 の RAND factor: RAND ∈ [-0.1, 0.1]）を乗じた値を加算して thundering herd を防ぐ（`rand::rng().random::<f64>()` で [0, 1) を生成し `-0.1 + r * 0.2` でスケーリング）
- Request（RFC 3315 Section 18.1.1）: OPTION_CLIENTID + **OPTION_SERVERID**（採用 Advertise のサーバー DUID）+ OPTION_IA_PD（Advertise 内容を転記）+ **OPTION_ORO**（Solicit と同一内容）。新たな Transaction ID を使用

**Renew/Rebind サイクル**:

- Renew（T1 到達後、RFC 3315 Section 18.1.3）:
  - OPTION_CLIENTID + **OPTION_SERVERID** + OPTION_IA_PD + **OPTION_ORO**（Solicit と同一内容: `OPTION_IA_PD`=25・`OPTION_S46_CONT_MAPE`=94）を含める（RFC 3315 必須 + RFC 7598 Section 5 SHOULD: Renew でも S46 オプションを明示的に要求することでサーバーが確実に S46 オプションを返すようにする）
  - Reply に OPTION_UNICAST（code=12）がある場合はそのアドレスへユニキャスト、ない場合は `ff02::1:2`（All_DHCP_Relay_Agents_and_Servers）へマルチキャスト（RFC 3315 Section 18.1.3 の fallback。`ff05::1:3` はサイトスコープであり多くの ISP 環境でルーティングされないため使用しない）
  - **Transaction ID**: T1 到達時（Renew 交換の開始時）に新しい Transaction ID を生成し、T2 到達まで同じ Transaction ID で再送する（RFC 3315 Section 14: 「同一メッセージの再送には同じ Transaction ID を使用すること」。Section 15.1 の「新規生成」規定は新しいメッセージ交換の開始時のみに適用されるものであり、再送には適用されない）
  - 再送間隔: 初回 10 秒・最大 10 秒（T2 到達まで固定。RFC 3315 Section 14 の推奨する指数バックオフ（REN_MAX_RT=600s）は採用せず単純な固定間隔とする。T1-T2 間隔が短い環境では再送頻度が高くなるが、MAP-E 専用デーモンとして許容事項とする）
- Rebind（T2 到達後、RFC 3315 Section 18.1.4）:
  - OPTION_CLIENTID + OPTION_IA_PD + **OPTION_ORO**（Solicit と同一内容: `OPTION_IA_PD`=25・`OPTION_S46_CONT_MAPE`=94）を含める（**OPTION_SERVERID は含めない**。RFC 3315 Section 18.1.4 では特定サーバーを対象としないため禁止。OPTION_ORO は RFC 7598 Section 5 SHOULD）
  - 宛先: `ff02::1:2`（All_DHCP_Relay_Agents_and_Servers）
  - **Transaction ID**: T2 到達時（Rebind 交換の開始時）に新しい Transaction ID を生成し、リース有効期限まで同じ Transaction ID で再送する（RFC 3315 Section 14 準拠。Renew と同様の理由）
  - 再送間隔: 初回 10 秒・最大 30 秒
- リース有効期限後に Reply が得られない場合: `self.params = None` にリセットして Solicit からやり直す。この間 `client.rs` はイベントを送出しないため **`runner.rs` の `DaemonState.params` は変更されず、既存の MAP-E 設定（nftables・トンネル・ルート）はそのまま維持される**

**Reply 処理**:

- 通常 Reply（MAP Rule + IA_PD あり）: `parse_ia_pd_info(data, Some(iaid))` を呼び出してプレフィックス・T1/T2/valid_lifetime を取得し、`Both` イベントを送出する。取得した T1/T2 を `self.renew_deadline` / `self.rebind_deadline`（`Instant::now() + Duration::from_secs(t1/t2)` として保持）にセットし、valid_lifetime を `self.lease_expiry`（`Instant::now() + Duration::from_secs(valid_lifetime)` として保持）に保存する
- Renew/Rebind Reply に `OPTION_S46_CONT_MAPE` がない場合（ISP 実装依存）: 既存 `pending_map_rules` を維持したまま `IaPdReceived` イベントを送出（MAP Rule キャッシュは更新しない）。T1/T2/valid_lifetime は更新する
- トップレベル Status Code が `Success`（0）以外 → error ログ + Solicit からやり直し（`self.params = None`）
- IA_PD 内の Status Code は `parse_ia_pd_info` が `None` を返すことで通知
- OPTION_IA_PD が含まれない・`parse_ia_pd_info` が `None` → warn ログ + 次の Renew/Rebind タイマーまで待機（サーバー実装バグとみなす）

**停止処理**:

- `runner.rs` から `CancellationToken`（`tokio_util::sync::CancellationToken`）を受け取り、SIGTERM/SIGINT で即時中断
- Renew/Rebind の `tokio::time::sleep` は `tokio::select!` で cancellation token と競合させて即時中断可能にする
- リース有効期限内（`Instant::now() < self.lease_expiry`）であれば **DHCPv6 Release**（msg-type=8、OPTION_CLIENTID + OPTION_SERVERID + OPTION_IA_PD、RFC 3315 Section 18.1.6 必須）を送信してから終了
  - `tokio::time::timeout(Duration::from_secs(2), ...)` でラップ（fire-and-forget。失敗は warn ログで無視）
  - `self.params = None` の状態では Release を送信しない
- **DHCPv6 Reconfigure（msg-type=10）**: サポートしない。受信時は破棄して warn ログを出力する

#### ステップ 4-3: `dhcpv6/mod.rs`（`DhcpV6Receiver` trait）

```rust
#[cfg(target_os = "linux")]
trait DhcpV6Receiver: Send {
    fn run(
        self: Box<Self>,
        tx: tokio::sync::mpsc::Sender<DhcpV6Event>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> impl Future<Output = Result<()>> + Send;
}
```

- Rust 2024 edition では `async fn in trait` が安定しているため `async_trait` crate は不要（`impl Future` の返り値型は RPIT として記述）
- **dispatch 方式: enum dispatch を使用する**。RPITIT（Return Position `impl Trait` in Trait）は各実装型ごとに異なる Future 型を持つため `dyn DhcpV6Receiver` にはできない（object-safe でない）。`runner.rs` では `DhcpV6Mode::Capture` / `DhcpV6Mode::Client` による分岐を `match` で行い、それぞれの具体型（`CaptureReceiver` / `ClientReceiver`）を直接 `tokio::spawn` する。`Box<dyn DhcpV6Receiver>` は使用しない。`DhcpV6Receiver` trait は型制約および将来の拡張性のために定義し、`runner.rs` は `match config.dhcpv6_mode` で dispatch する
- `DhcpV6Mode::Capture` / `DhcpV6Mode::Client` はどちらも `#[cfg(target_os = "linux")]` でのみ利用可能
- `client.rs` 全体を `#[cfg(target_os = "linux")]` で囲む（`nix` が Linux 限定依存のため）
- 非 Linux で起動した場合: `runner::start` の `#[cfg(not(target_os = "linux"))]` ブランチで `error!("MAP-E daemon は Linux 専用です")` を出力して `Err` を返す
- `runner.rs` の `select!` ループ内の `lease_rx` 受信ブランチも `#[cfg(target_os = "linux")]` で囲む
- 非 Linux ビルドでは SIGTERM + SIGINT の 2 系統のみの `select!` ブランチとなる（`dhcpv6_rx` / `lease_rx` チャネルは作成しない）

#### ステップ 4-4: `daemon/runner.rs` stub（Phase 4 時点）

- 起動時に `config.map_rules_cache_file` を読み込み、存在すれば `DaemonState.pending_map_rules` へ復元する
- **Phase 4 時点の実装範囲**（全 7 ステップのうち以下のみ）:
  - (1) PID ファイル原子的作成・二重起動防止チェック
  - (2) ディレクトリ作成（`fs::create_dir_all`）
  - (3) MAP Rule キャッシュ読み込み
  - (7) `DhcpV6Receiver` 起動・`select!` イベントループ開始
- (4) 起動時クリーンアップは Phase 6 完成後、(5)(6) `lease_watcher` 関連は Phase 5 完成後に、それぞれ Phase 8 統合時に追加する
- `client` モードの DUID 保存先（`/var/lib/mapecd/`）のディレクトリ作成はこの時点で先行実装しておく

#### ステップ 4-5: `daemon/runner.rs`（MAP Rule キャッシュ保存）

`DhcpV6Event::Both` 受信ハンドラ内で `config.map_rules_cache_file` へ MAP Rule を JSON 形式（`serde_json`）で保存する。保存失敗は warn ログで続行する。

`DhcpV6Receiver`（capture/client モード）が使用するイベント型（`dhcpv6/mod.rs` に定義する）:

```rust
enum DhcpV6Event {
    IaPdReceived(Ipv6Net),                  // IA_PD のみ更新。送出元:
                                            //   - capture/client モードで S46 なし Reply 受信時（dhcpv6_rx チャネル）
    Both { rules: Vec<MapRule>, ia_pd: Ipv6Net }, // MAP Rule + IA_PD 両方更新。送出元:
                                            //   - capture/client モードの通常 DHCPv6 Reply（dhcpv6_rx チャネル）
}
```

`lease_watcher` 専用のイベント型（`dhcpv6/mod.rs` に定義する）:

```rust
/// lease_watcher タスクが送出するイベント。IA_PD のみを運ぶ専用型。
/// DhcpV6Event と型を分けることで、lease_rx チャネルには IA_PD 以外を
/// 送出できないことを型システムで保証する（コンパイル時強制）。
struct LeaseEvent(pub Ipv6Net);
```

`runner.rs` は **2 本の独立した `tokio::sync::mpsc` チャネル** を保持する:

- **`dhcpv6_rx`**: `DhcpV6Receiver`（capture または client モード）から受け取る（型: `Receiver<DhcpV6Event>`）。`IaPdReceived` または `Both` を送出する。**`Option<Receiver<DhcpV6Event>>` として保持し**、`recv()` が `None` を返した場合はビジーループを防ぐため `dhcpv6_rx = None` にセットしてブランチを無効化する（詳細は「設計上の重要事項」の `DhcpV6Receiver タスク異常終了` 欄参照）。チャネルバッファサイズ: **16**（DHCPv6 イベントは頻繁には発生しないためバックプレッシャーは問題にならないが、起動直後のキャッシュ＋初回 Reply の連続送出を吸収できる程度の余裕を持たせる）
- **`lease_rx`**: `lease_watcher` から受け取る（型: `Receiver<LeaseEvent>`）。**`Option<Receiver<LeaseEvent>>` として保持する**。チャネルバッファサイズ: **4**（inotify イベントは連続して発生しうるが、runner.rs 側が即時消費するため小さな値で十分）

`runner.rs` の `select!` ループでは両チャネルを並列に受信する。`lease_rx` からは `LeaseEvent(prefix)` を受け取り、`DhcpV6Event::IaPdReceived(prefix)` と同一のハンドラロジック（`DaemonState` 更新 → `try_compute` → 必要なら `apply`/`update`）に処理を渡す。

`capture` / `client` モードの DHCPv6 Reply には IA_PD と MAP Rule の両方が含まれるため常に `Both` を送出する。`lease_watcher` は IA_PD のみを提供するため `LeaseEvent` を送出する。`runner.rs` は `Both` 受信時にキャッシュファイルへ MAP Rule を保存する。

`capture` モードで IA_PD オプションを含まない DHCPv6 Reply（例：Confirm への Reply）をキャプチャした場合は、パース結果を破棄してイベント送出をスキップする（`parse_ia_pd` が `None` を返した場合）。`capture` モードで IA_PD は存在するが `OPTION_S46_CONT_MAPE` が含まれない Reply をキャプチャした場合は、`client` モードと同様に既存の `pending_map_rules` を維持したまま `IaPdReceived` イベントを送出する（ISP 実装によっては Renew/Rebind Reply に S46 オプションを含まない場合がある）。

テスト: `capture.rs` と `client.rs` のパケット解析部分は `parser.rs` に委譲し単体テスト済みとする。`capture.rs` の宛先 IPv6 アドレスフィルタリングロジック（リンクローカルアドレス一致判定）は `nix::ifaddrs::getifaddrs()` をモック化して単体テストを実施する（一致時のみイベント送出、不一致時はスキップ、アドレス取得失敗時はチェックをスキップして全パケットを処理）。`DhcpV6Receiver` の mock 実装を用意し上位レイヤのテストに使用。キャッシュファイルの読み書きは純粋関数として分離して単体テスト。

### Phase 5: IA_PD 監視（Linux inotify 依存）

目標: systemd-networkd のリースファイル変化を検知して再計算をトリガー。capture/client モードと独立した IA_PD 更新源として動作し、どちらか早い方が `DaemonState.pending_ia_pd` を更新する。

| ステップ | 内容 |
| --- | --- |
| 5-1 | `dhcpv6/lease_watcher.rs` に inotify 監視ループ（nix::sys::inotify）。監視対象ディレクトリ `/run/systemd/netif/leases/` が存在しない場合は `warn` ログを出力して `lease_watcher` タスクを終了する（`runner.rs` は `lease_rx = None` として自然に吸収する）。**既知の制限事項**: タスク終了後に systemd-networkd が遅延起動してディレクトリが作成されても再検知は行わない。このような環境では mapecd を systemd-networkd の起動後に起動するよう `systemd` の `After=systemd-networkd.service` 依存関係を設定すること。タスクの自動再試行は本実装のスコープ外とする |
| 5-2 | systemd-networkd `.leases` ファイルパース（`X-NTP-Servers` ではなく `X-DELEGATED-PREFIX` フィールドを抽出）。ファイル命名規則: systemd-networkd は `/run/systemd/netif/leases/<ifindex>` という形式でリースファイルを生成する（拡張子なし）。`upstream_interface` に対応する ifindex は `nix::net::if_::if_nametoindex()` で取得し、監視対象ファイルパスを `/run/systemd/netif/leases/<ifindex>` として構成する。inotify は親ディレクトリ `/run/systemd/netif/leases/` に対して `IN_CLOSE_WRITE` および `IN_MOVED_TO` イベントを監視し、イベントが発生したファイル名が対象 ifindex に一致する場合のみパースを実施する |
| 5-3 | tokio channel 経由でイベント送信 |
| 5-4 | `daemon/runner.rs` 起動シーケンスで inotify 監視（`lease_watcher` タスク起動）を先に開始し、その後 `parse_lease_file` を直接呼び出してリースファイルの初回読み込みを行い、取得できた場合は `IaPdReceived` イベントとして即時送信する。この順序（inotify 登録 → 初回読み込み）により、登録前のファイル更新を見落とさない。起動シーケンスの `(4) リースファイル初回読み込み` ステップは「`lease_watcher` タスク起動後かつイベントループ開始前に `parse_lease_file` を呼び出す」と読み替える。これにより capture モードで MAP Rule キャッシュと組み合わせた起動直後の即時設定適用を可能にする |

テスト: ファイルパースロジックは純粋関数として分離し単体テスト。inotify 部分は `#[ignore]` タグ付き統合テスト。起動時一回読み込みのパスもモック経由でテスト。

### Phase 6: Netlink 操作（Linux rtnetlink 依存）

目標: CE IPv6 アドレス付与・CE IPv4 アドレス付与・トンネル作成・ルート設定を Netlink 経由で実行。

> **Phase 6 着手前の前提確認**: `rtnetlink` 0.14 で `RTM_GETLINK`（MTU 取得）が高レベル API でサポートされているかを確認する。サポートされていない場合は `Cargo.toml` の `[target.'cfg(target_os = "linux")'.dependencies]` セクションに `netlink-packet-route = "0.19"` を追加してから着手する。

| ステップ | 内容 |
| --- | --- |
| 6-1 | `netlink/addr.rs` - `add_ce_ipv6_addr`, `del_ce_ipv6_addr`（プレフィックス長は `/128`）および `add_ce_ipv4_addr`, `del_ce_ipv4_addr`（トンネルインターフェースへの inet ファミリ付与、プレフィックス長は `/32`） |
| 6-2 | 詳細は下記参照 |
| 6-3 | 詳細は下記参照 |

MTU 値の算出: `ip6tnl` は IPv4 パケットを IPv6 でカプセル化するため、オーバーヘッドは IPv6 ヘッダ 40 バイト。WAN インターフェースの MTU から 40 を引いた値をトンネル MTU として設定する（典型値: 1500 - 40 = 1460）。`Config` の `tunnel_mtu` フィールドで上書き可能とする。

#### ステップ 6-2: `netlink/tunnel.rs`

- **`get_link_mtu`**: RTM_GETLINK で `upstream_interface` の現在 MTU を取得
  - 失敗した場合（インターフェース未存在等）は `MapEError::NetlinkError` を返し `apply` を中止（MTU 不明のままトンネルを作成すると断片化の原因になるため）
  - `config.tunnel_mtu` が明示指定されている場合は `get_link_mtu` をスキップしてその値を使用する
- **`create_ip6tnl`**: パラメータ: `mode ipip6`、`encaplimit 0`（RFC 2473 のカプセル化深さ制限を無効化してネスト問題を防ぐ）、`remote <br_address>`、`local <ce_ipv6>`、`dev <upstream_interface>`（アンダーレイデバイスを明示し、ルーティングテーブルへの依存を排除）、`mtu <value>`
  - 作成後に RTM_GETLINK で ifindex を取得し `DaemonState.tunnel_ifindex` を更新する
- **`delete_ip6tnl`**: トンネルを削除する
- パラメータ変更時は delete → create の順で再作成する（RTM_NEWLINK による上書き更新は行わない）

#### ステップ 6-3: `netlink/route.rs`

- **`add_default_route`**: IPv4 デフォルトルートをトンネル経由に設定
  - 実行前に RTM_GETROUTE で既存の IPv4 デフォルトルート（dst=0.0.0.0/0）を列挙し、存在するものをすべて削除してからトンネル経由のルートを追加する（メトリック競合防止）
  - 削除失敗は warn ログで続行する
- **`del_default_route`**: トンネル経由のデフォルトルートのみを削除する（oif でフィルタ）
  - 以前存在していた他のデフォルトルートは復元しない（MAP-E 専用ルーターとして運用する前提。復元は設計上のスコープ外）

テスト: `NetlinkHandle` trait で抽象化し mock 使用。Linux CI 統合テストは `#[cfg_attr(not(ci_linux), ignore)]`。

### Phase 7: nftables 管理

目標: ポートセットを nftables ルールセットとして原子的に適用。

イングレス方向（BR → CE）の IPv6 デカプセルはカーネルの `ip6tnl` ドライバが担う。セキュリティ上、`br_address` 以外の送信元から届いた IPv6 カプセル化パケットを DROP する `prerouting` フィルタを追加する。本実装は **単一 BR アドレス前提**の設計とする。anycast 運用で複数の物理 BR が同一 anycast アドレスを共有する場合は問題ないが、OPTION_S46_BR が複数エントリを返す構成（Phase 3-2 で最初の BR のみ採用）での複数 BR への同時対応は設計スコープ外とする。IPv4-in-IPv6 のプロトコル番号は 4 であり、nftables では `ip6 nexthdr 4` と記述する（`ipip` キーワードはバージョンによって解釈が異なるため数値を使用する）。

NAPT44 の送信元ポート制限: `masquerade to :@port_ranges` 構文（nft 0.9.3 以降 / Linux 5.14 以降）を使用し、新規コネクションのポート割り当てを PSID セットに限定する。これにより `th sport @port_ranges` のような既存コネクションへのマッチ依存を避け、確実にポート範囲を制限する。

`generate_ruleset` が生成するルール骨格:

```nftables
add table ip mapecd
flush table ip mapecd
add table ip6 mapecd
flush table ip6 mapecd


table ip mapecd {
    set port_ranges {
        type inet_service
        flags interval
        elements = { <port_range_1>, <port_range_2>, ... }
    }

    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "<tunnel_interface>" masquerade to :@port_ranges
    }

    chain forward {
        type filter hook forward priority filter;
        oifname "<tunnel_interface>" tcp flags syn \
            tcp option maxseg size set rt mtu
        iifname "<tunnel_interface>" tcp flags syn \
            tcp option maxseg size set rt mtu
    }
}

table ip6 mapecd {
    chain prerouting {
        type filter hook prerouting priority filter;
        ip6 saddr != <br_address> ip6 nexthdr 4 drop
    }
}
```

TCP MSS クランプ（`tcp option maxseg size set rt mtu`）によりトンネル MTU に合わせた MSS 調整を行い、大きな TCP パケットによる接続断を防ぐ。`oifname` （CE → BR 方向の SYN）および `iifname`（BR → CE 方向の SYN-ACK）の両方向でクランプする。BR → CE 方向のパケットは ip6tnl でデカプセルされた後に IPv4 として `forward` チェーンを通過するため、`iifname` ルールが有効に機能する。

| ステップ | 内容 |
| --- | --- |
| 7-1 | `nftables/manager.rs` に `generate_ruleset` でルール文字列生成（egress NAT + ingress BR フィルタ） |
| 7-2 | `CommandExecutor` trait（`async fn execute(&self, input: &str) -> Result<()>`）を定義し、本番実装として `nft -f -` へのパイプ実行（`tokio::process::Command`）を行う `NftExecutor` を実装する。テスト用の `MockExecutor` も同ステップで定義する |
| 7-3 | 原子的入れ替え（flush table → 新ルール適用） |

テスト: `generate_ruleset` は純粋関数としてスナップショットテスト。`CommandExecutor` trait で mock 可能に。`port_ranges` が空の場合（`calc_port_ranges` のバグ防止）は `MapEError::EmptyPortRanges` を返し nftables 適用を中止する（`elements = {}` の interval set は nft バージョンによりエラーになるため）。`calc_port_ranges` は通常 `a=0,k=0` のケースでも `1..=65535` を返すため空にはならないが、`lifecycle.apply` / `lifecycle.update` の冒頭でガード節として確認する。

### Phase 8: デーモンコア統合

目標: 全モジュールを統合し、起動・更新・終了ライフサイクルを完成。

`status` / `stop` コマンドは PID ファイル経由で動作する:

- `start`: 二重起動防止チェック後にデーモン起動し、PID ファイル（`config.pid_file`）を作成
- `status`: PID ファイルを読み込み `/proc/<pid>/status` の存在確認で生死判定 `#[cfg(target_os = "linux")]`。出力形式: `running (pid=<PID>)` または `stopped`。非 Linux では PID ファイルを読み込み `libc::kill(pid as libc::pid_t, 0)`（POSIX）でプロセス生死を確認する（`libc` は `[dependencies]` に追加済みのため `#[cfg]` なしで使用可能。`start` の二重起動防止チェックと同じ方式）
- `stop`: PID ファイルから PID を取得し SIGTERM を送信する。PID ファイルの削除はデーモン自身が cleanup 完了後に行う（`stop` コマンド側では削除しない。競合による二重起動防止チェック崩壊を防ぐため）

二重起動防止チェック（`start` コマンド実行時）:

1. PID ファイルが存在しない → 起動続行
2. PID ファイルが存在する → PID を読み込み `/proc/<pid>/status`（Linux）または `libc::kill(pid as libc::pid_t, 0)`（非 Linux）でプロセス生死を確認
   - プロセスが生存中 → `error!("already running (pid={})", pid)` を出力して終了
   - プロセスが存在しない（前回の異常終了残留）→ warn ログを出力して PID ファイルを削除し起動続行

| ステップ | 内容 |
| --- | --- |
| 8-1 | `daemon/state.rs` に `DaemonState` 型定義 |
| 8-2 | 詳細は下記参照 |
| 8-3 | 詳細は下記参照 |
| 8-4 | `main.rs` からコマンドに応じて `start` / `status` / `stop` を呼び分け |
| 8-5 | `start` コマンド起動時に権限チェックを実施 `#[cfg(target_os = "linux")]`。`nix::unistd::getuid()` で root 判定（UID=0）または `/proc/self/status` の `CapEff` で `CAP_NET_RAW`（bit 13）・`CAP_NET_ADMIN`（bit 12）を確認。`client` モード選択時はさらに **`CAP_NET_BIND_SERVICE`（bit 10）** も確認する（UDP port 546 への bind に必要）。不足している場合は error ログを出力して即終了する |
| 8-6 | `start` コマンド起動時に `nft --version` を実行し、nft コマンドの存在確認を行う `#[cfg(target_os = "linux")]`。存在しない場合は error ログを出力して即終了する（バージョン要件 0.9.3+ の警告も出力する）。また `/proc/version` を読み込んでカーネルバージョンを確認し、`masquerade to :@port_ranges` に必要な Linux 5.14 未満の場合は warn ログを出力する（即終了はしない）。非 Linux ビルドではこの確認ステップ全体をスキップする（`#[cfg(target_os = "linux")]` で分離） |

#### ステップ 8-2: `daemon/lifecycle.rs`（`apply` / `update` / `cleanup`）

**`apply` の構築順序**（各ステップ番号は `update` の差分判定に対応）:

1. sysctl 設定: **まず現在値を `original_ip_forward` / `original_ipv6_forward` に保存**してから `ip_forward=1` / `ipv6 forwarding=1` を書き込む（保存を書き込みより先に行うことで cleanup 時の復元範囲を最大化する）
2. CE IPv6 アドレス付与（`upstream_interface` に /128）
3. ip6tnl トンネル作成（`tunnel_interface`）→ RTM_GETLINK で ifindex を取得して `DaemonState.tunnel_ifindex` を更新
4. CE IPv4 アドレス付与（`tunnel_interface` に /32。トンネル作成後に実施）
5. IPv4 デフォルトルート追加（トンネル経由）
6. nftables ルールセット適用

**`update` の差分更新**（`has_changed` が true の場合のみ呼び出される）:

| 変化フィールド | 実行するステップ |
| --- | --- |
| `port_ranges` のみ変化 | Step 6 のみ再実行 |
| `ce_ipv6` が変化 | Steps 2〜6 を再実行（旧 /128 削除 → 新 /128 付与 → トンネル delete → create → IPv4 アドレス付与 → ルート追加 → nftables 適用） |
| `br_address` のみ変化（`ce_ipv6` は不変） | Steps 3〜6 を再実行（トンネル delete → create） |
| `ce_ipv4` が変化（`ce_ipv6`・`br_address` は不変） | Steps 4〜6 を再実行 |

> **注意**: `ce_ipv6` が変化した場合は必ず Step 2（`upstream_interface` への /128 アドレス変更）も伴う。Steps 3〜6 だけでは古い CE IPv6 アドレスが upstream interface に残存し、ip6tnl の `local` パラメータとアドレス付与が不一致になる。

**`cleanup` の削除順序**（`apply` の逆順）:

1. nftables テーブル削除（`delete table ip mapecd` / `delete table ip6 mapecd`）
2. IPv4 デフォルトルート削除（`tunnel_interface` の oif でフィルタ）
3. ip6tnl トンネル削除
4. CE IPv4 アドレス削除（トンネル削除と同時に消滅するが、統一性のためステップとして残す。"no such device" は warn で無視）
5. CE IPv6 アドレス削除（`upstream_interface` から /128 を削除）
6. sysctl 復元: `original_ip_forward` が `Some(v)` の場合のみ書き戻し。復元後は `None` にリセットする（残留値で次の `apply` が誤った元値を保存しないようにするため）

**エラー処理**:

- `apply` が `Err` を返した場合 → `runner.rs` は即座に `cleanup` を呼び出し `self.params = None` にリセット（残留設定をクリア）
- `update` が `Err` を返した場合 → 同様に `cleanup` → フルリセット → 次の DHCPv6 イベントで `apply` から再構築（部分的な差分更新状態のまま運用すると整合性が保証できないため）

`#[cfg(target_os = "linux")]` 分離対象: sysctl 書き込み・`netlink/` 呼び出し・`nftables/` の `nft -f -` 実行

#### ステップ 8-3: `daemon/runner.rs`（完全版イベントループ）

**`select!` の受信対象**（Linux: 4 系統、非 Linux: 2 系統）:

1. `dhcpv6_rx`: `DhcpV6Receiver`（capture / client モード）からの `DhcpV6Event`
2. `lease_rx`: `lease_watcher` からの `LeaseEvent`（`#[cfg(target_os = "linux")]` のみ）
3. SIGTERM（`tokio::signal`）
4. SIGINT（`tokio::signal`）

**チャネル管理**（ビジーループ防止）:

- `dhcpv6_rx` は `Option<Receiver<DhcpV6Event>>` として保持する
- `lease_rx` は `Option<Receiver<LeaseEvent>>` として保持する（専用型のため `DhcpV6Event` と型が異なる）
- どちらも `recv()` が `None` を返した場合（送信側が drop された）は error ログ出力後に `None` に設定してブランチを無効化する
- `select!` 内では `if let Some(ref mut rx) = dhcpv6_rx`（および `lease_rx`）の条件付き形式で記述する

**起動シーケンス（全 7 ステップ）**:

1. PID ファイルの原子的作成・二重起動防止チェック（`create_new` → `AlreadyExists` ならプロセス生死確認）← **最初に行うことで以降の処理中も二重起動を防止**
2. ディレクトリ作成（`fs::create_dir_all`: `/run/mapecd/` と `/var/lib/mapecd/`）
3. MAP Rule キャッシュ読み込み（`map_rules_cache_file`）
4. 起動時クリーンアップ（残留設定クリア）
5. `lease_watcher` タスク起動（inotify 登録を先行させるため `parse_lease_file` より前）`#[cfg(target_os = "linux")]`
6. リースファイル初回読み込み（`parse_lease_file` 直接呼び出し）`#[cfg(target_os = "linux")]`
7. `DhcpV6Receiver` 起動・`select!` イベントループ開始

**SIGTERM/SIGINT 受信時の終了フロー**:

- cleanup（nftables → ルート → トンネル → アドレス削除）→ PID ファイル削除
- SIGHUP による設定リロードはサポートしない（DHCPv6 イベント駆動で自動更新されるため不要）

**PID ファイルの作成**: `OpenOptions::new().write(true).create_new(true)` で原子的に作成（POSIX の `O_CREAT + O_EXCL` 相当。TOCTOU 競合を排除）

テスト: 各コンポーネントを mock 差し込み可能な構造にし、lifecycle の状態遷移テスト。変化がない場合は設定更新しないことを確認。二重起動防止の各分岐（生存中・残留 PID ファイル・未存在）を単体テスト。

---

## 主要な型定義

### `config.rs`

```rust
#[derive(Debug, Deserialize)]
struct Config {
    upstream_interface: String,        // WAN 側インターフェース名（DHCPv6 キャプチャ対象）
    tunnel_interface:   String,        // 作成する ip6tnl トンネル名
    #[serde(default)]
    dhcpv6_mode:        DhcpV6Mode,    // デフォルト: Capture
    #[serde(default = "default_pid_file")]
    pid_file:           PathBuf,       // デフォルト: /run/mapecd.pid
    #[serde(default = "default_map_rules_cache_file")]
    map_rules_cache_file: PathBuf,     // デフォルト: /run/mapecd/rules.cache（capture モード再起動時の MAP Rule 復元用）
    #[serde(default = "default_duid_file")]
    duid_file:          PathBuf,       // デフォルト: /var/lib/mapecd/duid（client モードの DUID 永続化。/var/lib/ に配置しリブートをまたいで同一 DUID を保持）
    #[serde(default)]
    tunnel_mtu:         Option<u32>,   // 省略時は WAN MTU - 40 を自動算出
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "lowercase")]   // TOML では "capture" / "client" と記述する
enum DhcpV6Mode {
    #[default]
    Capture,   // AF_PACKET でスニッフィング（systemd-networkd と競合しない）
    Client,    // 独立 DHCPv6 クライアント（事前に systemd-networkd の DHCPv6 を無効化すること）
}
```

CLI オプション:

- `--config <PATH>`: 設定ファイルパス（デフォルト: `/etc/mapecd/config.toml`）
- `--log-level <LEVEL>`: ログレベル `error` / `warn` / `info` / `debug` / `trace`（デフォルト: `info`）

### `map/rule.rs`

```rust
// Serialize: MAP Rule キャッシュファイル（serde_json）への書き込みに必要
// Deserialize: キャッシュファイルからの復元 および DHCPv6 パーサーでの構築に必要
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapRule {
    ipv6_prefix: Ipv6Net,
    ipv4_prefix: Ipv4Net,
    ea_length: u8,
    br_address: Ipv6Addr,
    port_params: PortParams,
}

// MapRule と同様に Serialize + Deserialize が必要（MapRule に内包されるため）
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PortParams {
    psid_offset: u8,   // a: ポート先頭の除外ビット数。Port(R,j) 式の j の範囲 [0, 2^a - 1]（v6プラス: 4）
    psid_length: u8,   // k: PSID のビット長（v6プラス: 8）
}

// MapeParams はキャッシュ対象外（ce_ipv4 等は IA_PD + MapRule から毎回再計算するため）
// Serialize は不要。Debug + Clone のみ付与する
#[derive(Debug, Clone)]
struct MapeParams {
    rule: MapRule,
    ce_ipv4: Ipv4Addr,
    ce_ipv6: Ipv6Addr,    // /128 でアドレス付与（RFC 7597 Section 5.2）
    psid: u16,
    port_ranges: Vec<RangeInclusive<u16>>,
}
```

### `map/calc.rs`

```rust
// ce_prefix: IA_PD で委譲された IPv6 プレフィックス（DaemonState.pending_ia_pd から渡す）
fn extract_ea_bits(ce_prefix: &Ipv6Net, rule: &MapRule) -> Result<u64>
// extract_ea_bits が成功した後は ea_bits のビット幅が rule によって保証されるため、
// derive_ipv4_and_psid は常に成功する（infallible）。Result を返さない。
fn derive_ipv4_and_psid(ea_bits: u64, rule: &MapRule) -> (Ipv4Addr, u16)
// RFC 7597 Section 5.2 に従い以下の 128 ビットアドレスを構成する:
//   [Rule IPv6 prefix (r bits)] | [EA-bits (ea_length bits)] | [0-pad] |
//   [IPv4 addr (32 bits, bits 80-111)] | [PSID << (16-k) (16 bits, bits 112-127)]
// 下位 48 ビット（IPv4 addr + PSID）は ea_bits と rule から内部導出する。
// 呼び出し元が ipv4/psid を別途渡す必要はない（ea_bits と rule から一意に決まるため）。
fn build_ce_ipv6(rule: &MapRule, ea_bits: u64) -> Ipv6Addr
fn compute_mape_params(ce_prefix: &Ipv6Net, rule: &MapRule) -> Result<MapeParams>
```

### `map/port_set.rs`

```rust
// Port(R, j) = R * 2^(a+k) + PSID * 2^a + j
// R ∈ [1, 2^(16-a-k) - 1],  j ∈ [0, 2^a - 1]
fn calc_port_ranges(psid: u16, params: &PortParams) -> Vec<RangeInclusive<u16>>
```

### `daemon/state.rs`

```rust
struct DaemonState {
    params: Option<MapeParams>,
    tunnel_ifindex: Option<u32>,
    pending_map_rules: Vec<MapRule>,     // 揃い待ち（複数ルール）
    pending_ia_pd: Option<Ipv6Net>,      // 揃い待ち（IA_PD 委譲プレフィックス）
    original_ip_forward: Option<bool>,  // apply 前の net.ipv4.ip_forward 値（cleanup 時に復元）
    original_ipv6_forward: Option<bool>, // apply 前の net.ipv6.conf.all.forwarding 値（cleanup 時に復元）
}

impl DaemonState {
    // 比較対象フィールド: ce_ipv4, ce_ipv6, rule.br_address, port_ranges の 4 フィールド
    // いずれか 1 つでも異なれば true を返す。
    // psid は port_ranges に反映済みのため個別比較不要。
    // rule.ipv6_prefix / ipv4_prefix / ea_length は ce_ipv4・ce_ipv6・port_ranges が
    // 同一であれば network 設定に差異が生じないため比較対象外とする。
    // update ロジック（lifecycle.rs）は has_changed=true を前提に、変化したフィールドの
    // 組み合わせ（ce_ipv6 変化 → Steps 2〜6、br_address のみ変化 → Steps 3〜6、
    // ce_ipv4 変化 → Steps 4〜6、port_ranges のみ変化 → Step 6 のみ）で必要な操作を決定する。
    fn has_changed(&self, new_params: &MapeParams) -> bool
    // 両方揃えば pending_ia_pd に最長一致する MapRule を pending_map_rules から選択し
    // compute_mape_params(pending_ia_pd, matched_rule) を呼び出す
    // 最長一致の定義: pending_ia_pd が rule.ipv6_prefix のネットワークアドレス空間に含まれる
    //   （ce_prefix.network() の先頭 rule.ipv6_prefix.prefix_len() ビットが rule.ipv6_prefix と一致する）
    //   ルールのうち rule.ipv6_prefix.prefix_len() が最大のものを選択する。
    //   同一プレフィックス長のルールが複数ある場合は Vec 内で先に現れたもの（受信順）を優先する。
    // 返り値の区別:
    //   - Ok(None):  データ未揃い。pending_ia_pd が None または pending_map_rules が空のいずれか。
    //               runner.rs は何もせず次のイベントを待つ（pending_ia_pd のリセット不要）
    //   - Ok(Some): 正常計算完了。runner.rs は apply/update を呼び出す
    //   - Err:      CE prefix がマッチするルールなし（データは揃っていたが計算不可）。
    //               runner.rs は error! ログ + pending_ia_pd = None にリセット
    fn try_compute(&self) -> Result<Option<MapeParams>>
}

// runner.rs における DaemonState.params 更新の責務:
// try_compute が Ok(Some(new_params)) を返した場合:
//   - self.params が None（初回）→ lifecycle.apply(new_params) を呼び出す
//   - self.params が Some(old) かつ has_changed(new_params) が true → lifecycle.update(old, new_params) を呼び出す
//   - いずれも成功後に self.params = Some(new_params) へ更新する（runner.rs の責務）
// self.params の更新は lifecycle 呼び出しの成功後に行う（失敗時は旧 params を保持する）
```

---

## 設計上の重要事項

| 事項 | 方針 |
| --- | --- |
| systemd-networkd との DHCPv6 競合 | デフォルト `capture` モードで AF_PACKET ソケットを使用し UDP 546 バインドを回避。`client` モード使用時は systemd-networkd / NetworkManager の DHCPv6 を事前に無効化すること |
| Linux 専用コードの分離 | `#[cfg(target_os = "linux")]` で分離。`map/` および `dhcpv6/parser.rs` は非依存に保ち macOS でも `cargo test --lib` が通る。`dhcpv6/capture.rs`・`dhcpv6/client.rs`（`nix::ifaddrs` 依存）・`dhcpv6/lease_watcher.rs`・`netlink/` 配下はすべて `#[cfg(target_os = "linux")]` で囲む。`daemon/runner.rs` の `start` ロジック本体（`DhcpV6Receiver` 起動・`lease_watcher` 起動を含む全処理）も `#[cfg(target_os = "linux")]` ブロックに配置し、`#[cfg(not(target_os = "linux"))]` ブロックでは `error!("MAP-E daemon は Linux 専用です")` を出力して即終了する（`main.rs` から呼び出す `runner::start` 関数の中で分岐する） |
| IA_PD と MAP Rule の揃い待ち | `DaemonState` に `pending_map_rules: Vec<MapRule>` と `pending_ia_pd` を保持し両方揃った時点で適用。`try_compute` は `pending_ia_pd` に最長一致するルールを選択する。最長一致は「`pending_ia_pd` の先頭 `rule.ipv6_prefix.prefix_len()` ビットが `rule.ipv6_prefix` のネットワークアドレスと一致する」ルールの中でプレフィックス長が最大のものと定義する。同一プレフィックス長のルールが複数存在する場合は `Vec` 内で先に現れたもの（受信順）を優先する（v6プラスなど実運用では同一プレフィックス長の競合は発生しないため単純な受信順優先で十分と判断）。DHCPv6 受信（capture/client）が両方を提供するが、lease_watcher による IA_PD 更新も受け付ける |
| `try_compute` のエラー処理 | `Result<Option<MapeParams>>` を返す。`Ok(None)` は `pending_ia_pd` が `None` または `pending_map_rules` が空のいずれかのデータ未揃い状態を示す（`pending_map_rules` が空の場合は `Err` ではなく `None` を返すことに注意）。`Err` は CE prefix が全ルールと不一致など計算失敗を示す。`runner.rs` は `Err` を受け取った場合、`error!` ログを出力して `pending_ia_pd` を `None` にリセットし（無効な IA_PD を破棄）、次の IA_PD 更新イベントを待つ。`pending_map_rules` は破棄しない（MAP Rule 自体は正しい可能性があるため）。誤ったキャッシュ由来の MAP Rule がマッチしない場合は、次の DHCPv6 Reply（`Both` イベント）受信時に `pending_map_rules` が上書きされる |
| 単一トンネル前提 | `pending_map_rules` に複数ルールがある場合でも、`pending_ia_pd` に最長一致する 1 つのルールに対して 1 つの ip6tnl トンネルのみを作成する。複数トンネルは本実装のスコープ外 |
| nftables 原子的更新 | `add table` で事前にテーブルを作成してから `flush table` → 全ルール再定義のワンショットで `nft -f -` にパイプ。`flush table` 単体は対象テーブル非存在時にエラーを返す nft バージョンがあるため、`add table` を先行させて冪等性を確保する |
| nftables イングレスフィルタ | `br_address` 以外の送信元からの `ipip`（nexthdr 4）パケットを DROP。正規の BR からのカプセル化パケットのみ受け入れる |
| SIGTERM クリーンアップ順序 | nftables → ルート → トンネル → CE IPv4 アドレス → CE IPv6 アドレスの逆順削除。各ステップのエラーは warn ログで続行。CE IPv4 アドレスはトンネルインターフェース上に付与されているため、トンネル削除と同時に消滅する。しかし起動時クリーンアップとの実装統一のためステップとして残し、"no such device" エラーは warn ログで無視する |
| nftables テーブル削除方針 | SIGTERM/SIGINT による終了時クリーンアップでは `delete table ip mapecd` / `delete table ip6 mapecd` を使用してテーブルを完全に削除する（`flush table` ではなく）。他の nftables ルールセットに空テーブルが残存しないようにするため。起動時クリーンアップ（残留設定のクリア）でも同様に `delete table` を使用し、テーブル非存在時のエラーは warn ログで無視する。apply 時のみ `add table` → `flush table` → 全ルール再定義のパターンを使用する |
| 起動時クリーンアップ | 前回の異常終了後の残留設定を確実にクリアするため、SIGTERM と同順（nftables テーブル delete → IPv4 デフォルトルート削除 → トンネルリンク削除 → CE IPv4 アドレス削除 → CE IPv6 アドレス削除）で試みてから再構築する。各ステップのエラーは warn ログで続行。**CE IPv6 アドレスの削除**: 起動時は `DaemonState.params` が存在しないため削除対象の /128 アドレスが不明。`RTM_GETADDR` で `upstream_interface` 上の全 IPv6 アドレスを列挙し、プレフィックス長が /128 のものをすべて削除する。**注意**: この操作は MAP-E 以外の目的で付与された /128 アドレス（例: 管理用途で手動設定したアドレス）も削除対象となる。`upstream_interface` は MAP-E 専用として使用し、他用途の /128 アドレスを同一インターフェースに付与しないことをシステム管理者が保証すること（この前提条件は README に明記する） |
| 起動時クリーンアップとトンネル名競合 | 起動時クリーンアップでは `tunnel_interface` と同名のインターフェースを問答無用で削除する。mapecd 以外のプロセスが同名のトンネルを作成していた場合も削除対象となる。`tunnel_interface` 名は他プロセスと重複しない値をユーザーが責任を持って設定すること。削除失敗（"not found" 等）は warn ログで続行する |
| CE IPv6 アドレスのプレフィックス長 | `/128` で付与（RFC 7597 推奨）。トンネルの `local` パラメータにも同アドレスを使用 |
| CE IPv4 アドレス付与 | トンネルインターフェースに inet ファミリで `/32` プレフィックス長で付与。NAPT44 のソースアドレスおよびトンネル `local` パラメータに必要 |
| トンネル MTU | WAN インターフェース MTU - 40 バイト（IPv6 ヘッダオーバーヘッド）を自動算出。`config.tunnel_mtu` で上書き可能。WAN インターフェースの MTU が運用中に変化した場合の自動追従は本実装スコープ外とし、再起動で対応する |
| トンネルパラメータ変更 | RTM_NEWLINK による上書きは行わず、delete → create の順で再作成する |
| ログ出力先 | `tracing-subscriber` を使用。`/run/systemd/journal/socket` が存在する場合は `tracing-journald` を優先し、そうでない場合は stderr に出力 |
| status / stop の IPC | PID ファイル（`config.pid_file`）経由。`stop` は SIGTERM を送信するのみ。PID ファイルの削除はデーモン自身が cleanup 完了後に行う。`status` の `/proc/<pid>/status` 確認は `#[cfg(target_os = "linux")]` で分離 |
| S46 オプションパーサー | `dhcproto` は外枠の TLV 走査のみに使用。S46 固有オプション (94/89/90/93) は手書きバイトパーサーで実装 |
| IPv4/IPv6 フォワーディング | `lifecycle.apply` 時に `/proc/sys/net/ipv4/ip_forward` および `/proc/sys/net/ipv6/conf/all/forwarding` へ直接書き込み（`"1"\n`）で設定し、`lifecycle.cleanup` 時に各々元の値に戻す。外部コマンド依存を避けるため `sysctl` コマンドではなくファイル書き込みを使用する。NAPT44 動作および ip6tnl 経由の IPv6 ルーティングに必須。元の値は `DaemonState.original_ip_forward` / `original_ipv6_forward` に保存する。これらの操作は `#[cfg(target_os = "linux")]` で分離し、非 Linux ビルドではスキップする。`/proc/sys/net/ipv6/conf/all/forwarding` を使用する理由: `ip6tnl` インターフェースは動的に作成されるため、起動時に per-interface の `/proc/sys/net/ipv6/conf/<iface>/forwarding` が存在しない。Linux カーネルの仕様上、`conf/all/forwarding=1` は既存および新規作成インターフェースの forwarding を一括有効化するため、動的に作成される ip6tnl にも確実に適用される。per-interface 設定のみでは ip6tnl 作成前後のタイミングによって forwarding が有効にならないリスクがある。**副作用**: `conf/all/forwarding=1` は LAN 側インターフェースを含む全インターフェースの IPv6 フォワーディングを有効にする。これは CE ルーターとして LAN-WAN 間のルーティングを行う用途では意図した動作であり、設計上の許容事項とする |
| sysctl 異常終了時の復元 | panic などの異常終了時は `lifecycle.cleanup` が呼ばれないため `ip_forward` 等の sysctl 値は復元されない。これは設計上の許容事項とする。次回の正常起動→終了サイクルで復元される。起動時クリーンアップは nftables・ルート・トンネルの残留設定のみを対象とし、sysctl の復元は行わない |
| `lifecycle.apply` 途中失敗時の sysctl 状態 | `apply` のステップ (1) で `ip_forward=1` を書き込んだ後にステップ (2) 以降が失敗した場合、`original_ip_forward` が保存されていれば cleanup で復元できるが、保存前に失敗した場合は復元できない。これは「sysctl 異常終了時の復元」と同様の設計上の許容事項とする。次回の正常起動→終了サイクルで復元される。`original_ip_forward` の保存はステップ (1) の冒頭（ファイル書き込み前）に行うことで、この許容事項の発生範囲を最小化できる。**実装上の注意**: Phase 8-2 のステップ (1) は「①現在値を `original_ip_forward` に保存 → ② `ip_forward=1` を書き込む」の 2 段階で実装すること |
| `lifecycle.apply` 途中失敗時のネットワーク残留状態 | `apply` がステップ (3)（トンネル作成）以降で失敗した場合、作成済みのトンネルや付与済みアドレスがカーネルに残留する。`runner.rs` は `apply` が `Err` を返した場合、即座に `lifecycle.cleanup` を呼び出して残留設定をクリアする（`self.params` は `None` のままにする）。`cleanup` も失敗した場合は次回起動時の起動時クリーンアップが対処する。これは設計上の許容事項とする |
| `lifecycle.update` 失敗時のリカバリ | `update` が `Err` を返した場合（差分更新の途中失敗）、ネットワーク設定が中途半端な状態になりうるため、`runner.rs` は即座に `lifecycle.cleanup` を呼び出してネットワーク設定全体をクリアし `self.params = None` にリセットする（部分的な差分更新状態のまま運用を続けると整合性が保証できないため、フルリセットで一貫性を確保する）。その後は次の DHCPv6 イベント受信時に `apply` から再構築する。`cleanup` も失敗した場合は次回起動時の起動時クリーンアップが対処する |
| `lease_rx` チャネルの型制約 | `lease_watcher` が送出できるイベントは IA_PD のみであるため、`DhcpV6Event` と型を分けた専用型 `LeaseEvent(Ipv6Net)` を使用する。`lease_rx` チャネルの型を `Receiver<LeaseEvent>` とすることで、MAP Rule 等の誤送出を型システムにより防ぐ（コンパイル時強制）。`lease_watcher.rs` では `Sender<LeaseEvent>` に対して `LeaseEvent(prefix)` を送出するだけでよく、不変条件コメントや `unreachable!()` は不要 |
| `lease_watcher` タスク異常終了 | `lease_watcher` タスクがパニック等で終了した場合、`runner.rs` の `lease_rx.recv()` は `None` を返す。**`None` を受け取った後に同一 `recv()` を再度呼ぶと即座に `None` を返し続けるため、`select!` ループがビジーループになる**。これを防ぐため、`runner.rs` では `lease_rx` を `Option<Receiver<LeaseEvent>>` として保持し、`None` 受信時に `error!` ログを出力した後 `lease_rx = None` とセットしてブランチを無効化する（`select!` 内の該当ブランチは `if let Some(ref mut rx) = lease_rx` の形で条件付きに記述する）。DHCPv6 受信（capture/client）による IA_PD 更新は引き続き機能するため即座に終了しない。ただし再起動によるリースファイル変化は検知できなくなる旨を warn ログで補足する。タスクの自動再起動は本実装のスコープ外とする |
| `DhcpV6Receiver` タスク異常終了 | `DhcpV6Receiver` タスクがパニック等で終了した場合、`runner.rs` の `dhcpv6_rx.recv()` は `None` を返す。`lease_rx` と同様のビジーループを防ぐため、`dhcpv6_rx` を `Option<Receiver<DhcpV6Event>>` として保持し（`lease_rx` の `Option<Receiver<LeaseEvent>>` と同一の `Option` パターン）、`None` 受信時に `error!` ログを出力した後 `dhcpv6_rx = None` とセットしてブランチを無効化する（`select!` 内の該当ブランチは `if let Some(ref mut rx) = dhcpv6_rx` の形で条件付きに記述する）。`dhcpv6_rx` が無効化されると新規 DHCPv6 Reply および MAP Rule 更新がすべて停止するため、`error!` ログにデーモン再起動を促すメッセージを含める。タスクの自動再起動は本実装のスコープ外とする |
| lease 期限切れ後の既存設定維持 | `client` モードでリース有効期限後に Reply が得られず Solicit からやり直す場合（`self.params = None` にリセット）、`client.rs` はイベントを送出しない。そのため `runner.rs` の `DaemonState.params` は変更されず、既存の MAP-E 設定（nftables・ip6tnl・ルート）はそのまま維持される。Solicit が成功して新たな Reply を受信した時点で差分更新が行われる。これにより Solicit 再試行中も通信継続が可能となる（設計上の意図した動作） |
| nftables NAPT44 ポート制限 | `masquerade to :@port_ranges` 構文（nft 0.9.3+ / Linux 5.14+）で新規コネクションのポート割り当てを PSID セットに限定する |
| TCP MSS クランプ | `forward` チェーンで `tcp option maxseg size set rt mtu` を `oifname`（CE → BR 方向）および `iifname`（BR → CE 方向）の両方向に適用し、トンネル MTU に起因する TCP 接続断を防ぐ。BR → CE 方向は ip6tnl デカプセル後の IPv4 パケットが `forward` チェーンを通過するため `iifname` ルールが有効に機能する |
| MAP Rule キャッシュ | DHCPv6 Reply 受信時（`Both` イベント）に MAP Rule を `config.map_rules_cache_file` へ JSON 形式（`serde_json`）で保存する。起動時にキャッシュファイルが存在すれば `pending_map_rules` へ復元し、lease_watcher の初回 IA_PD 取得と組み合わせて即時設定適用を可能にする。capture モード再起動時の設定適用遅延（最大 T1 タイマー分）を回避するための仕組み |
| ランタイムディレクトリ作成 | `runner.rs` の起動シーケンス内で `fs::create_dir_all` により `/run/mapecd/`（`map_rules_cache_file` のデフォルト親ディレクトリ）および `/var/lib/mapecd/`（`client` モードの DUID ファイル配置先）を作成する。両ディレクトリとも `create_dir_all` は冪等なため、`Capture` モードでも無条件に作成する（モードによる条件分岐は不要）。DUID ファイルは `config.duid_file`（デフォルト: `/var/lib/mapecd/duid`）に配置し、リブートをまたいで同一 DUID を保持する。`/var/lib/mapecd/` は将来的に systemd ユニットの `StateDirectory=mapecd` で管理することを想定しているが、現状は `create_dir_all` で代替する。**起動シーケンスの順序**: (1) PID ファイルの原子的作成・二重起動防止チェック（`create_new` → `AlreadyExists` ならプロセス生死確認）← **最初に行うことで以降の処理中も二重起動を防止** → (2) ディレクトリ作成（`create_dir_all`）→ (3) MAP Rule キャッシュ読み込み（`map_rules_cache_file`）→ (4) 起動時クリーンアップ（残留設定クリア）→ (5) `lease_watcher` タスク起動（inotify 登録を先行させるため）→ (6) リースファイル初回読み込み（`parse_lease_file` 直接呼び出し）→ (7) `DhcpV6Receiver` 起動・`select!` イベントループ開始。Step (5) で inotify を先に登録することで、Step (6) との間のファイル更新をイベントとして捕捉できる。PID ファイルを Step (1) で作成することにより、起動時クリーンアップや初期化処理中に別プロセスが同時起動するのを防ぐ。 |
| nftables masquerade の適用範囲 | `postrouting` チェーンの `oifname "<tunnel_interface>" masquerade` はトンネルインターフェースへの送出パケットのみに作用する。MAP-E 以外のトラフィックはトンネル経由でルーティングされないため、`ip saddr` による CE IPv4 フィルタは追加しない（インターフェースベースの制限で十分）。`ip6tnl` は L3 デバイスであり IPv4 パケットの送出インターフェースとして `oifname` で正しく識別できることを実機テストで確認すること（IPv4 デフォルトルートがトンネルを向いていれば `oifname` は期待通り機能するが、環境差異がある可能性を排除するため Phase 8 の統合テストに含める） |
| `rtnetlink` 直接依存 | `rtnetlink` 0.14 は `RTM_GETLINK`（MTU 取得）を高レベル API でサポートしていない可能性がある。Phase 6 着手前の前提確認（Phase 6 冒頭参照）で `netlink-packet-route` crate の要否を確定する。必要な場合は `Cargo.toml` の `[target.'cfg(target_os = "linux")'.dependencies]` セクションに `netlink-packet-route = "0.19"` を追加する |
| シグナルハンドリング | SIGTERM と SIGINT の両方を `tokio::signal` で受信し、同一の cleanup フロー（nftables → ルート → トンネル → アドレス削除 → PID ファイル削除）を実行する。SIGHUP による設定リロードはサポートしない（DHCPv6 イベント駆動で自動更新されるため不要） |
| Rust edition / 最低バージョン | `Cargo.toml` に `edition = "2024"` を設定する。Rust edition 2024 のコンパイルには **Rust 1.85 以降**が必要（edition 2024 は Rust 1.85 で安定化）。RPITIT（Return Position `impl Trait` in Traits）および `async fn in trait` の言語仕様自体は Rust 1.75 で安定化済みだが、edition 2024 の要件が上位のため最低バージョンは **1.85** となる。`Cargo.toml` に `rust-version = "1.85"` を設定し、最低バージョン要件をビルド時に強制する。`async_trait` crate は使用しない |
| 二重起動防止 | `start` 実行時に PID ファイルを `OpenOptions::new().write(true).create_new(true)` で原子的に作成する。`ErrorKind::AlreadyExists` の場合のみ既存 PID を読んでプロセス生死を確認し、生存中はエラー終了、残留（プロセス非存在）の場合は warn ログ → 削除 → 再作成する。この方式により TOCTOU 競合を排除する |
| IAID（ifindex）の安定性 | `client` モードでは IAID に `nix::net::if_::if_nametoindex(upstream_interface)` で取得した ifindex を使用する。Linux の ifindex はリブート後に変化しうる（カーネルによる動的割り当て）ため、DUID が同一でも IAID が変わるとサーバー側でバインディングが更新される場合がある。実運用上は同一インターフェース名であれば ifindex が変化しないケースが大半であり、変化した場合もサーバーは新しい Solicit として処理して新たなプレフィックスを委譲するため動作継続上の問題はない。設計上の許容事項とする |
| `nftables` コマンド実行の Linux 限定 | `nftables/manager.rs` の `generate_ruleset` は純粋文字列生成のため全プラットフォームでコンパイル可能。ただし `nft -f -` コマンド実行（Step 7-2）は Linux のみで有効であり、`lifecycle.apply` 内の呼び出しを `#[cfg(target_os = "linux")]` で分離する |
| nft コマンド確認 | `start` 実行時に `nft --version` で nft コマンドの存在を確認する `#[cfg(target_os = "linux")]`。非 Linux ビルドではこの確認をスキップする。存在しない場合はエラーで即終了する。バージョン確認は `nft --version` の stdout（例: `nftables v1.0.9 (Old Doc Yak, 8 November 2023)`）から正規表現 `v(\d+)\.(\d+)\.(\d+)` でセマンティックバージョンをパースし、0.9.3 未満の場合は warn ログを出力する（即終了はしない。適用時に nft がエラーを返すことで検知）。バージョン文字列のパースに失敗した場合（想定外のフォーマット）も warn ログを出力して続行する。加えて `/proc/version` からカーネルバージョンをパースし、`masquerade to :@port_ranges` に必要な Linux 5.14 未満の場合は warn ログを出力する（即終了はしない） |

---

## モジュール間の依存グラフ

```text
main.rs
  ├── cli.rs
  ├── config.rs
  └── daemon/runner.rs
       ├── daemon/state.rs ── map/rule.rs
       │    └── map/calc.rs ──── map/rule.rs
       │         └── map/port_set.rs
       ├── daemon/lifecycle.rs
       │    ├── map/rule.rs        （MapeParams 型参照のみ。calc.rs は呼ばない）
       │    ├── netlink/addr.rs    [Linux only]
       │    ├── netlink/tunnel.rs  [Linux only]
       │    ├── netlink/route.rs   [Linux only]
       │    └── nftables/manager.rs
       └── dhcpv6/
            ├── capture.rs        [Linux only]
            ├── client.rs         [Linux only]
            ├── parser.rs
            └── lease_watcher.rs  [Linux only]
```

依存の方向は常に上位（ランタイム）→ 下位（純粋ロジック）。`map/` は外部 crate に依存しない純粋計算層として設計。  
`lifecycle.rs` は計算済みの `MapeParams` を受け取って netlink/nftables 操作を行うだけであり、`calc.rs` や `state.rs` には依存しない（型参照として `map/rule.rs` の `MapeParams` のみ参照）。`calc.rs` は `state.rs` の `try_compute` から呼び出される。

---

## テスト戦略

### 純粋ロジック層（Linux 不要・高カバレッジ目標）

| モジュール | 方針 |
| --- | --- |
| `map/calc.rs` | EA-bits 抽出・CE IPv6 構成のビット演算を網羅テスト |
| `map/port_set.rs` | v6プラス（a=4, k=8, PSID=5）での期待値テスト。ポート総数 240 を必須検証。`a=0` のエッジケースも検証 |
| `config.rs` | 最小構成・フルサンプル・不正値の 3 ケースで serde デシリアライズ検証 |
| `dhcpv6/parser.rs` | キャプチャしたバイト列をテストベクタとして埋め込み |
| `nftables/manager.rs` | `generate_ruleset` 出力の文字列スナップショットテスト（egress NAT + ingress フィルタ両方を検証） |
| `daemon/state.rs` | `try_compute` の `None`（未揃い）・`Ok(Some(...))`（正常計算）・`Err`（不一致エラー）の 3 パターンを単体テスト |
| `daemon/lifecycle.rs` | `apply`・`update`・`cleanup` の状態遷移を mock 差し込みで検証。変化がない場合（`has_changed` が false）は netlink/nftables 呼び出しが発生しないことを確認 |
| `daemon/runner.rs` | 二重起動防止の各分岐（生存中・残留 PID ファイル・未存在）を単体テスト |

### システムコール依存層（Linux CI + `#[ignore]` タグ）

> **非 Linux（macOS 等）でのテスト範囲について**: `cargo test --lib` が通る保証は `map/` および `dhcpv6/parser.rs` の純粋ロジック層のみ。`daemon/` 層は `DhcpV6Receiver` trait が `#[cfg(target_os = "linux")]` でのみ定義されるため、`runner.rs` の単体テストは Linux 環境（または CI）で実施する。`lifecycle.rs` は mock 差し込みで純粋関数的なテストが可能だが、`netlink/` 呼び出しのモック化が必要なため同様に Linux CI 前提とする。

| モジュール | 方針 |
| --- | --- |
| `netlink/` | `NetlinkHandle` trait で抽象化し mock 使用。統合テストは `#[ignore]` |
| `dhcpv6/capture.rs` | パケット解析部分は parser.rs に分離してテスト |
| `dhcpv6/lease_watcher.rs` | ファイルパース部分のみ純粋関数として分離してテスト |
| `nftables/manager.rs` | `CommandExecutor` trait で `nft` コマンド呼び出しを mock 可能に |
