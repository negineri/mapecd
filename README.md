# mapecd

MAP-E (Mapping of Address and Port with Encapsulation) クライアントデーモン。

RFC 7597 に準拠した MAP-E 設定を DHCPv6 経由で取得し、Linux ネットワークスタックを自動設定します。

## 概要

mapecd は、ISP が提供する MAP-E サービスに接続するためのデーモンです。以下の処理を自動化します。

1. DHCPv6 (RFC 7598 OPTION_S46_CONT_MAPE) で MAP-E ルールを取得
2. EA-bits・PSID・ポートセットを計算
3. Linux Netlink を通じてトンネル・ルート・インターフェースを設定

## インストール

```bash
cargo build --release
sudo cp target/release/mapecd /usr/local/sbin/
```

## 使い方

```bash
# デーモンとして起動（eth0 で ISP に接続する場合）
mapecd start --interface eth0

# 現在の MAP-E 設定を表示
mapecd status

# ネットワーク設定を削除してクリーンアップ
mapecd stop
```

### オプション

| オプション | 短縮形 | デフォルト                | 説明               |
| ---------- | ------ | ------------------------- | ------------------ |
| `--config` | `-c`   | `/etc/mapecd/config.toml` | 設定ファイルのパス |

## 設定ファイル

`/etc/mapecd/config.toml`（ISP から取得できない場合の手動設定）:

```toml
# ログレベル（RUST_LOG 環境変数で上書き可能）
log_level = "info"

# MAP-E ルール手動設定（DHCPv6 で取得できない場合のみ）
[map_rule]
ipv6_prefix = "2001:db8::/32"
ipv4_prefix = "192.0.2.0/24"
ea_length = 8
psid_offset = 6
```

環境変数プレフィックス `MAPECD_` でも設定可能です（例: `MAPECD_LOG_LEVEL=debug`）。

## ログ

`RUST_LOG` 環境変数でログレベルを制御します。

```bash
RUST_LOG=debug mapecd start --interface eth0
```

## 対応プラットフォーム

- Linux（Netlink を使用するため Linux 必須）

## 関連仕様

- [RFC 7597](https://www.rfc-editor.org/rfc/rfc7597) — Mapping of Address and Port with Encapsulation (MAP-E)
- [RFC 7598](https://www.rfc-editor.org/rfc/rfc7598) — DHCPv6 Options for Configuration of Softwire Address and Port-Mapped Clients
