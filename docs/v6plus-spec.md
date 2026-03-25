# v6プラス 技術仕様

## 概要

v6プラスは、JPIX（株式会社日本インターネットエクスチェンジ）が提供する MAP-E（RFC 7597）ベースの IPv4 over IPv6 サービスである。
複数の ISP が v6プラスを採用しており、本ドキュメントでは初期実装ターゲットとしての仕様を整理する。

---

## MAP-E パラメータ（v6プラス固有値）

| パラメータ | 値 | 説明 |
| --- | --- | --- |
| PSID offset (a) | 4 | ポートセット先頭のオフセットビット数 |
| PSID length (k) | 8 | PSID のビット長 |
| 1 アドレスあたりの共有ユーザー数 | 2^k = 256 | PSID 値の数 |
| ユーザーあたり利用可能ポート数 | 240 | 後述の計算参照 |

> MAP Rule（BMR: Basic Mapping Rule）の IPv4/IPv6 プレフィックスおよび BR の IPv6 アドレスは
> DHCPv6 `OPTION_S46_CONT_MAPE` から動的に取得する。
> プレフィックスは ISP や契約によって異なるため、ハードコードしない。

---

## DHCPv6 オプション構造（RFC 7598）

v6プラスでは WAN 側の DHCPv6 Advertise / Reply に以下のオプションが含まれる。

```
OPTION_S46_CONT_MAPE (code 94)          ← MAP-E コンテナ
  └─ OPTION_S46_RULE (code 89)          ← BMR（Basic Mapping Rule）
       ├─ flags           (1 byte)       ← bit0: FMR フラグ
       ├─ ea-len          (1 byte)       ← EA-bits 長（ビット数）
       ├─ prefix4-len     (1 byte)       ← IPv4 プレフィックス長
       ├─ ipv4-prefix     (4 bytes)      ← IPv4 プレフィックス
       ├─ ipv6-prefix-len (1 byte)       ← IPv6 プレフィックス長
       ├─ ipv6-prefix     (可変長)       ← IPv6 プレフィックス
       └─ OPTION_S46_PORTPARAMS (code 93)
            ├─ offset     (4 bits)       ← PSID offset a = 4
            ├─ psid-len   (4 bits)       ← PSID length k = 8
            └─ psid       (2 bytes)      ← この CE の PSID 値
  └─ OPTION_S46_BR (code 90)            ← BR の IPv6 アドレス（16 bytes）
```

### 各フィールドの意味

- **ea-len**: EA-bits（Embedded Address bits）の長さ。IPv4 サフィックスと PSID の合計ビット数
- **PSID offset (a)**: 使用禁止ポート範囲の幅を `2^(a+k)` で定義する。a=4 の場合、R=0 のポート範囲（0〜4095）は使用禁止
- **PSID length (k)**: PSID のビット数。k=8 で 256 ユーザーが 1 つの IPv4 アドレスを共有
- **PSID**: この CE（Customer Edge）に割り当てられた Port Set ID

---

## IPv6 アドレスからのパラメータ導出

### EA-bits の抽出

IA_PD で委任された IPv6 プレフィックス（CE prefix）から EA-bits を抽出する。

```
CE IPv6 prefix:  [  MAP Rule IPv6 prefix  ][    EA-bits    ][ ... ]
                 |<---- rule-prefix-len --->|<-- ea-len --->|
```

**手順:**

1. DHCPv6 IA_PD で委任されたプレフィックス（例: `/48`）を取得する
2. MAP Rule の IPv6 プレフィックス長（rule-prefix-len）に続く ea-len ビットを抽出する
   ```
   ea_bits = (ce_prefix >> (prefix_len - rule_prefix_len - ea_len)) & ((1 << ea_len) - 1)
   ```

### IPv4 アドレスの導出

```
ipv4_suffix_len = 32 - prefix4_len
psid_bits       = ea_len - ipv4_suffix_len

ipv4_suffix = ea_bits >> psid_bits        ← EA-bits の上位ビット
psid        = ea_bits & ((1 << psid_bits) - 1)  ← EA-bits の下位ビット（= k ビット）

ipv4_addr   = ipv4_prefix | ipv4_suffix
```

> `psid_bits` は DHCPv6 の `OPTION_S46_PORTPARAMS` の psid-len（k）と一致する。
> また DHCPv6 の psid フィールド値とも一致することを検証する。

### CE の IPv6 アドレスの構成（RFC 7597 Section 5.2）

```
[  MAP Rule IPv6 prefix  ][ EA-bits ][ 0x0000...0000 ][ IPv4 addr ][ PSID ][ 00 ]
 <-- rule_prefix_len ---->           <----- pad ----->  <-- 32 --> <--16-->
```

具体的には:

```
ce_ipv6 = rule_ipv6_prefix
ce_ipv6[rule_prefix_len : rule_prefix_len+ea_len] = ea_bits
ce_ipv6[128-16-16 : 128-16]                       = ipv4_addr (32bits → 下位32bit)
ce_ipv6[128-16    : 128   ]                        = psid << (16 - k)
```

---

## ポートセットの計算（RFC 7597 Section 5.1）

PSID と offset、length から利用可能なポート番号集合を計算する。

### パラメータ

| 記号 | 値（v6プラス） | 説明 |
| --- | --- | --- |
| a | 4 | PSID offset |
| k | 8 | PSID length |
| m = 2^a | 16 | ポートインデックスの範囲 |
| N = 2^(16-a-k) | 16 | R の最大値 + 1（ポートブロック数） |

### ポート番号の算出式

```
Port(R, j) = R * 2^(a+k) + PSID * 2^a + j

ただし:
  R ∈ [1, N-1]  = [1, 15]    （R=0 は禁止ポート範囲）
  j ∈ [0, m-1]  = [0, 15]
```

### ポートセット例（PSID=5 の場合）

```
R=1:  1 * 4096 + 5 * 16 + [0..15] = 4176 〜 4191
R=2:  2 * 4096 + 5 * 16 + [0..15] = 8272 〜 8287
...
R=15: 15 * 4096 + 5 * 16 + [0..15] = 61536 〜 61551
```

合計: 15 範囲 × 16 ポート = **240 ポート / ユーザー**

### 禁止ポート範囲

R=0 に該当するポート（0〜4095）は使用禁止。ウェルノウンポート（0〜1023）を含む。

---

## nftables による NAPT 設定

MAP-E では PSID に属さないポートからの送出を禁止する必要がある。

### ポートマスクを使った判定

v6プラスの場合（a=4, k=8）、ポート番号の構造は以下の通り:

```
Port [15:12] = R     (4 bits)
Port [11:4]  = PSID  (8 bits)
Port [3:0]   = j     (4 bits)
```

あるポート `p` が自分の PSID に属するかの判定:

```
(p >> 4) & 0xFF == PSID  AND  (p >> 12) != 0
```

### nftables ルールセットのイメージ

```nftables
table ip mapecd {
  set allowed_ports {
    type inet_service
    flags interval
    elements = {
      4176-4191,   # R=1, PSID=5
      8272-8287,   # R=2, PSID=5
      # ... 以下 R=3〜15 の範囲
    }
  }

  chain postrouting {
    type nat hook postrouting priority srcnat;

    # MAP-E トンネル経由の IPv4 通信を PSID ポートセットで SNAT
    oifname "mape0" snat to <ipv4_addr>:{ <allowed_ports> }
  }
}
```

> ポート集合は PSID 更新時（DHCPv6 リース更新時）に原子的に入れ替える。

---

## トンネル設定

### インターフェースタイプ

`ip6tnl` タイプのトンネルを使用する（Linux kernel の `ip6_tunnel` モジュール）。

```bash
# 相当する ip コマンド（実装では Netlink を直接使用）
ip tunnel add mape0 mode ip4ip6 \
  local <CE_IPv6_addr> \
  remote <BR_IPv6_addr> \
  dev <wan_iface>
ip link set mape0 up
ip addr add <CE_IPv4_addr>/32 dev mape0
ip route add default dev mape0
```

### MTU

MAP-E では IPv6 カプセル化により MTU が減少する。

| 項目 | 値 |
| --- | --- |
| IPv6 ヘッダーオーバーヘッド | 40 bytes |
| 推奨 MTU（WAN が 1500 の場合） | 1460 bytes |

MSS クランプも併せて設定することが望ましい。

---

## 実装上の考慮事項

### DHCPv6 受信のタイミング

IA_PD と `OPTION_S46_CONT_MAPE` は同じ DHCPv6 Reply に含まれる場合と含まれない場合がある。

- 両方が揃ってから MAP-E パラメータを計算する
- IA_PD は systemd-networkd が取得するため、mapecd は `/run/systemd/netif/leases/<ifindex>` の変化を監視する

### リース更新時の挙動

| 変化 | 対応 |
| --- | --- |
| IA_PD プレフィックス変化 | 全パラメータ再計算・全設定更新 |
| MAP Rule 変化 | 全パラメータ再計算・全設定更新 |
| BR アドレス変化 | トンネルリモートエンドポイントのみ更新 |
| PSID 変化 | ポートセット・nftables ルール更新 |
| 変化なし | 何もしない |

### systemd-networkd との競合回避

- DHCPv6 クライアントポート（UDP 546）は systemd-networkd が使用中の可能性がある
- mapecd は `OPTION_S46_CONT_MAPE` 取得のために独立して DHCPv6 を購読するか、
  または systemd-networkd の DHCPv6 パケットをパケットキャプチャ（AF_PACKET）で傍受する方式を検討する

---

## 関連仕様・参考資料

- [RFC 7597](https://www.rfc-editor.org/rfc/rfc7597) — MAP-E アーキテクチャとアドレスマッピングルール
- [RFC 7598](https://www.rfc-editor.org/rfc/rfc7598) — DHCPv6 Options for MAP-E (`OPTION_S46_CONT_MAPE`)
- [RFC 7599](https://www.rfc-editor.org/rfc/rfc7599) — MAP-E アドレスマッピングルール詳細
- [v6プラス サービス](https://www.v6plus.jp/) — JPIX 公式サービスページ
