# mapecd 責務定義

## 概要

本ドキュメントは、mapecd が担うべき責務と、systemd-networkd など外部コンポーネントとの境界を定義する。

---

## 責務の分担

### systemd-networkd が担う領域（mapecd は関与しない）

| 処理 | 備考 |
|------|------|
| WAN インターフェースの有効化・リンク管理 | `systemd.network` で設定 |
| DHCPv6 IA_NA による WAN 側 IPv6 アドレス取得 | グローバルユニキャストアドレス |
| DHCPv6 IA_PD による IPv6 プレフィックス委任 | LAN 向けプレフィックスの取得・配布 |
| LAN インターフェースの IPv6 アドレス設定 | 委任プレフィックスから生成 |
| LAN 側 DHCPv4 / DHCPv6 サーバー | `systemd-networkd` + `systemd-resolved` |
| DNS リゾルバ設定 | `resolved` が担う |
| LAN 側インターフェースの作成・管理 | `systemd.netdev` で設定 |

### mapecd が担う領域

#### 1. DHCPv6 MAP-E オプションの受信

- WAN インターフェース上で DHCPv6 パケットを受信する
- `OPTION_S46_CONT_MAPE`（RFC 7598）を含むオプションを解析する
- systemd-networkd は MAP-E オプションを処理しないため、mapecd が独立した DHCPv6 受信処理を持つ

**入力**: WAN インターフェース上の DHCPv6 Advertise / Reply パケット
**出力**: MAP Rule (BMR/FMR)、Port Parameters (PSID offset, PSID length)

#### 2. MAP-E パラメータの計算

DHCPv6 で取得した MAP Rule と、systemd-networkd が取得した IA_PD 情報をもとに以下を計算する。

- **EA-bits の抽出**: IPv6 プレフィックスから Embedded Address bits を取り出す
- **IPv4 アドレスの決定**: IPv4 プレフィックスと EA-bits から CE の IPv4 アドレスを計算する
- **PSID の決定**: EA-bits から Port Set ID を導出する
- **利用可能ポートセットの計算**: PSID offset・PSID length・PSID から利用可能なポート範囲一覧を生成する
- **IPv6 CE アドレスの構成**: MAP Rule の IPv6 プレフィックスに EA-bits を埋め込む

**入力**: MAP Rule、IA_PD プレフィックス
**出力**: CE の IPv4 アドレス、CE の IPv6 アドレス、PSID、ポートセット

#### 3. WAN 側 IPv6 CE アドレスの設定

計算した CE の IPv6 アドレスを WAN インターフェース（または tunnel インターフェース）に付与する。

- Netlink `RTM_NEWADDR` で IPv6 アドレスを追加する
- 既存の MAP-E 由来アドレスがある場合は差し替える

**入力**: CE の IPv6 アドレス、WAN インターフェース名
**出力**: インターフェースへの IPv6 アドレス付与

#### 4. MAP-E トンネルインターフェースの作成・管理

- `ip6tnl` タイプのトンネルインターフェースを Netlink 経由で作成する（`RTM_NEWLINK`）
- トンネルのローカルエンドポイントとして CE の IPv6 アドレスを設定する
- トンネルのリモートエンドポイントとして BR（Border Relay）の IPv6 アドレスを設定する
- DHCPv6 リース更新時にトンネルパラメータを更新する
- 終了時にトンネルインターフェースを削除する

**入力**: CE IPv6 アドレス、BR IPv6 アドレス
**出力**: トンネルインターフェースの作成

#### 5. ルーティングの設定

- デフォルトルート（`0.0.0.0/0`）をトンネルインターフェース経由に設定する（`RTM_NEWROUTE`）
- MAP-E ルールに FMR が含まれる場合は対応するルートを追加する
- 既存の MAP-E 由来ルートと競合しないよう管理する

**入力**: トンネルインターフェース名、MAP Rule
**出力**: ルーティングテーブルへのエントリ追加

#### 6. NAPT ポート制限の設定

MAP-E では利用できるポート番号が PSID によって制限される。nftables を用いてこの制約を強制する。

- `ip mapecd` テーブルに SNAT ルールを設定し、送信を許可ポートセットに限定する（`masquerade to :@port_ranges`）
- `ip mapecd` テーブルの `forward` チェーンで TCP MSS クランプを設定する（`tcp option maxseg size set rt mtu`）
- `ip6 mapecd` テーブルでブリッジリレー以外からの IPv4-in-IPv6 カプセル受信をドロップする
- 設定更新時にルールセットを原子的に入れ替える（`nft -f -` への一括適用）
- nftables テーブル名は固定で `mapecd`

**入力**: ポートセット（利用可能ポート範囲一覧）、トンネルインターフェース名、BR IPv6 アドレス
**出力**: nftables ルールセットの適用

#### 7. IA_PD プレフィックスの監視

- systemd-networkd が `/run/systemd/netif/leases/` に書き出すリース情報を監視する
- IA_PD プレフィックスが変化した場合にパラメータ再計算・設定更新を行う

**入力**: `/run/systemd/netif/leases/<ifindex>` の変化
**出力**: 再計算トリガー

#### 8. 設定のライフサイクル管理

- 起動時: 既存の MAP-E 関連設定を検出し、必要に応じてクリーンアップしてから再設定する
- DHCPv6 リース更新時: 変化があった場合のみ設定を更新する
- 終了時（SIGTERM / SIGINT）: トンネルインターフェース・ルート・nftables ルールを削除してクリーンアップする

---

## 境界の整理

```
ISP
 │  DHCPv6 (IA_NA, IA_PD, OPTION_S46_CONT_MAPE)
 ▼
WAN インターフェース (例: eth0)
 │
 ├── systemd-networkd ─────────────────────────────────────────┐
 │    IA_NA → WAN IPv6 アドレス                                │
 │    IA_PD → /run/systemd/netif/leases/<ifindex>             │
 │                                                             │
 └── mapecd ───────────────────────────────────────────────────┤
      OPTION_S46_CONT_MAPE → MAP Rule 解析                     │
      IA_PD 監視 (/run/systemd/netif/leases/)                  │
      EA-bits / PSID / ポートセット計算                        │
      CE IPv6 アドレス計算・設定 (Netlink)                     │
      ip6tnl トンネル作成・管理 (Netlink)                      │
      デフォルトルート設定 (Netlink)                           │
      nftables NAPT ポート制限設定                             │
                                                               │
 ▼                                                             │
Linux ネットワークスタック ◄────────────────────────────────────┘
 │
 ├── LAN インターフェース (systemd-networkd が管理)
 │    IPv6 RA 配布、DHCPv4/v6 サーバー
 │
 └── WAN トンネル経由で IPv4 通信
```

---

## mapecd が扱わない事項（明示的除外）

| 項目 | 理由 |
|------|------|
| LAN 側インターフェースの作成・設定 | systemd-networkd の責務 |
| IPv4 アドレスの LAN 側への割り当て | systemd-networkd の責務 |
| DHCPv4 / DHCPv6 サーバー | systemd-networkd の責務 |
| DNS / mDNS | systemd-resolved の責務 |
| WAN 側リンクの物理管理 | systemd-networkd の責務 |
| ファイアウォール（MAP-E 以外） | 別途 nftables / firewalld で管理 |
| IPv6 RA（Router Advertisement）送出 | systemd-networkd の責務 |

---

## 関連仕様

- [RFC 7597](https://www.rfc-editor.org/rfc/rfc7597) — MAP-E アーキテクチャ
- [RFC 7598](https://www.rfc-editor.org/rfc/rfc7598) — DHCPv6 Options for MAP-E
- [RFC 7599](https://www.rfc-editor.org/rfc/rfc7599) — MAP-E のアドレスマッピングルール
