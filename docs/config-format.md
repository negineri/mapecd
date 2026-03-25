# 設定ファイル仕様

## ファイルパス

デフォルト: `/etc/mapecd/config.toml`

起動時に `--config <path>` オプションで変更できる。

---

## 完全なサンプル

```toml
# ── 全般設定 ──────────────────────────────────────────────────────────────

# ログレベル。RUST_LOG 環境変数で上書き可能。
# 有効値: "trace" | "debug" | "info" | "warn" | "error"
# デフォルト: "info"
log_level = "info"

# ── インターフェース設定 ───────────────────────────────────────────────────

# WAN 側インターフェース名（必須）
# systemd-networkd が管理する ISP 接続インターフェース
wan_interface = "eth0"

# MAP-E トンネルインターフェース名
# デフォルト: "mape0"
tunnel_interface = "mape0"

# トンネルインターフェースの MTU（バイト）
# IPv6 ヘッダー 40 bytes 分を差し引いた値を推奨
# デフォルト: 1460
tunnel_mtu = 1460

# TCP MSS クランプの有効化
# tunnel_mtu - 40(IPv4) - 20(TCP) = 1400 bytes に制限する
# デフォルト: true
mss_clamp = true

# ── DHCPv6 受信設定 ────────────────────────────────────────────────────────

[dhcpv6]
# DHCPv6 パケットの受信方式
# "capture" : AF_PACKET ソケットで wan_interface 上の DHCPv6 パケットを傍受する
#             systemd-networkd と UDP 546 ポートを共有できるため競合しない
#             （推奨）
# "client"  : 独立した DHCPv6 クライアントとして Solicit/Request を送信する
#             wan_interface で systemd-networkd の DHCPv6 が無効な場合に使用する
# デフォルト: "capture"
mode = "capture"

# ── systemd-networkd 連携 ─────────────────────────────────────────────────

[networkd]
# systemd-networkd が IA_PD リース情報を書き出すディレクトリ
# デフォルト: "/run/systemd/netif/leases"
lease_dir = "/run/systemd/netif/leases"

# ── nftables 設定 ─────────────────────────────────────────────────────────

[nftables]
# mapecd が管理する nftables テーブル名
# 他のルールセットと名前が衝突しないよう必要に応じて変更する
# デフォルト: "mapecd"
table_name = "mapecd"

# ── MAP-E ルール手動設定（オプション）────────────────────────────────────
#
# 通常は DHCPv6 OPTION_S46_CONT_MAPE から自動取得するため不要。
# DHCPv6 から取得できない場合や、設定を固定したい場合のみ指定する。
# このセクションを指定した場合、DHCPv6 からの MAP Rule は無視される。

# [map_rule]
# # IPv6 マッピングルールプレフィックス（CIDR 表記）
# ipv6_prefix = "2001:db8::/32"
#
# # IPv4 マッピングルールプレフィックス（CIDR 表記）
# ipv4_prefix = "192.0.2.0/24"
#
# # EA-bits 長（ビット数）
# ea_length = 16
#
# # BR（Border Relay）の IPv6 アドレス
# br_address = "2001:db8::1"
#
# # ポートパラメータ
# [map_rule.port_params]
# # PSID offset（a）: 使用禁止ポート範囲の幅を定義する
# psid_offset = 4
# # PSID length（k）: PSID のビット長
# psid_length = 8
```

---

## フィールド一覧

### トップレベル

| キー | 型 | 必須 | デフォルト | 説明 |
| --- | --- | --- | --- | --- |
| `log_level` | string | いいえ | `"info"` | ログレベル。`trace` / `debug` / `info` / `warn` / `error` |
| `wan_interface` | string | **はい** | なし | WAN 側インターフェース名 |
| `tunnel_interface` | string | いいえ | `"mape0"` | 作成するトンネルインターフェース名 |
| `tunnel_mtu` | integer | いいえ | `1460` | トンネル MTU（バイト） |
| `mss_clamp` | bool | いいえ | `true` | TCP MSS クランプの有効化 |

### `[dhcpv6]` セクション

| キー | 型 | 必須 | デフォルト | 説明 |
| --- | --- | --- | --- | --- |
| `mode` | string | いいえ | `"capture"` | DHCPv6 受信方式。`"capture"` または `"client"` |

#### `mode = "capture"` の動作

AF_PACKET ソケットを使って `wan_interface` 上の DHCPv6 パケット（UDP dst port 546）を受信する。
systemd-networkd が UDP 546 をバインドしていても競合しない。
ただし `CAP_NET_RAW` 権限が必要。

#### `mode = "client"` の動作

UDP 546 ポートをバインドし、DHCPv6 Solicit を送信してレスポンスを受信する。
`wan_interface` 上で systemd-networkd の DHCPv6 クライアントが無効な場合に使用する。
`CAP_NET_BIND_SERVICE` 権限が必要。

### `[networkd]` セクション

| キー | 型 | 必須 | デフォルト | 説明 |
| --- | --- | --- | --- | --- |
| `lease_dir` | string | いいえ | `"/run/systemd/netif/leases"` | systemd-networkd の IA_PD リースディレクトリ |

mapecd はこのディレクトリ内の `<ifindex>` ファイルを inotify で監視し、
IA_PD プレフィックスが変化したときにパラメータを再計算する。

### `[nftables]` セクション

| キー | 型 | 必須 | デフォルト | 説明 |
| --- | --- | --- | --- | --- |
| `table_name` | string | いいえ | `"mapecd"` | 管理する nftables テーブル名 |

### `[map_rule]` セクション（オプション）

DHCPv6 から取得できない場合の手動設定。このセクション全体がオプション。

| キー | 型 | 必須 | 説明 |
| --- | --- | --- | --- |
| `ipv6_prefix` | string | はい | IPv6 マッピングルールプレフィックス（CIDR 表記） |
| `ipv4_prefix` | string | はい | IPv4 マッピングルールプレフィックス（CIDR 表記） |
| `ea_length` | integer | はい | EA-bits 長（ビット数） |
| `br_address` | string | はい | BR の IPv6 アドレス |

### `[map_rule.port_params]` セクション（オプション）

`[map_rule]` を指定した場合のみ有効。

| キー | 型 | 必須 | 説明 |
| --- | --- | --- | --- |
| `psid_offset` | integer | はい | PSID offset（a）。v6プラスは `4` |
| `psid_length` | integer | はい | PSID length（k）。v6プラスは `8` |

---

## 環境変数による上書き

プレフィックス `MAPECD_` を付けた環境変数でほぼすべての設定を上書きできる。
ネストしたキーはアンダースコアで結合する。

| 環境変数 | 対応するキー |
| --- | --- |
| `MAPECD_LOG_LEVEL` | `log_level` |
| `MAPECD_WAN_INTERFACE` | `wan_interface` |
| `MAPECD_TUNNEL_INTERFACE` | `tunnel_interface` |
| `MAPECD_TUNNEL_MTU` | `tunnel_mtu` |
| `MAPECD_DHCPV6__MODE` | `dhcpv6.mode` |
| `MAPECD_NETWORKD__LEASE_DIR` | `networkd.lease_dir` |
| `MAPECD_NFTABLES__TABLE_NAME` | `nftables.table_name` |

---

## 最小構成例

WAN インターフェースのみ指定した最小構成。その他はすべてデフォルト値を使用する。

```toml
wan_interface = "eth0"
```

---

## v6プラス向け構成例

DHCPv6 `capture` モードで v6プラスに接続する典型的な設定。

```toml
wan_interface  = "eth0"
tunnel_interface = "mape0"
tunnel_mtu     = 1460
mss_clamp      = true
log_level      = "info"

[dhcpv6]
mode = "capture"
```
