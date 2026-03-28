#!/usr/bin/env python3
"""
v6plus MAP ルール生成スクリプト。

https://ipv4.web.fc2.com/map-e.html から 3 テーブル
（ruleprefix38 / ruleprefix31 / ruleprefix38_20）を取得・解析し、
src/map/v6plus_rules.rs を生成する。

使用方法:
    # URL から自動取得（デフォルト）
    python tools/gen_v6plus_rules.py --output src/map/v6plus_rules.rs

    # 既存の JS ファイルを使用
    python tools/gen_v6plus_rules.py --input docs/v6plus-maprule.js \
        --output src/map/v6plus_rules.rs

更新手順:
    1. 本スクリプトを実行する（--input 省略で自動取得）
    2. 生成物をコミットする

検証:
    cargo test -- v6plus でゴールデンテストと件数一致テストを実行する。
"""

import argparse
import hashlib
import re
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from typing import Optional


# ────────────────────────────────────────────────────────────────────
# テーブルパラメータ定義
# ────────────────────────────────────────────────────────────────────

# テーブルごとの固定パラメータ
# ea_length = 56 - ipv6_prefix_len を検証する
# ipv4_prefix_len = 32 - (ea_length - psid_length) を検証する
TABLE_PARAMS = {
    "ruleprefix38": {
        "ipv6_prefix_len": 38,
        "ea_length": 18,  # 56 - 38
        "psid_length": 8,
        "psid_offset": 4,
        "ipv4_prefix_len": 22,  # 32 - (18 - 8)
    },
    "ruleprefix31": {
        "ipv6_prefix_len": 31,
        "ea_length": 25,  # 56 - 31
        "psid_length": 8,
        "psid_offset": 4,
        "ipv4_prefix_len": 15,  # 32 - (25 - 8)
    },
    "ruleprefix38_20": {
        "ipv6_prefix_len": 38,
        "ea_length": 18,  # 56 - 38
        "psid_length": 6,
        "psid_offset": 6,
        "ipv4_prefix_len": 20,  # 32 - (18 - 6)
    },
}

# 生成順序（JS の分岐優先順に準拠）
TABLE_ORDER = ["ruleprefix38", "ruleprefix31", "ruleprefix38_20"]

# BR アドレス決定条件（優先順位順）
BR_ADDR_CONDITIONS = [
    # (prefix31_min, prefix31_max_exclusive, br_address)
    (0x24047A80, 0x24047A84, "2001:260:700:1::1:275"),
    (0x24047A84, 0x24047A88, "2001:260:700:1::1:276"),
    (0x240B0010, 0x240B0014, "2404:9200:225:100::64"),
    (0x240B0250, 0x240B0254, "2404:9200:225:100::64"),
]

# デフォルト BR アドレス（条件 1-3 に該当しない場合）
DEFAULT_BR_ADDR = "2001:380:a120::9"


# ────────────────────────────────────────────────────────────────────
# URL 取得・JS 抽出
# ────────────────────────────────────────────────────────────────────

DEFAULT_URL = "https://ipv4.web.fc2.com/map-e.html"


def fetch_and_extract_js(url: str) -> tuple[str, str]:
    """URL から HTML を取得し、テーブルを含む script ブロックを抽出する。

    Returns:
        (js_content, tmp_path) — 抽出した JS テキストと保存先の一時ファイルパス。
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; gen_v6plus_rules)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        html_bytes = resp.read()

    # 一時ファイルに HTML を保存
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".html", delete=False) as tmp:
        tmp.write(html_bytes)
        tmp_path = tmp.name

    html_content = html_bytes.decode("utf-8", errors="replace")

    # <script> タグ内のテキストをすべて抽出
    script_blocks = re.findall(
        r"<script[^>]*>(.*?)</script>",
        html_content,
        re.DOTALL | re.IGNORECASE,
    )

    # ruleprefix38 を含むブロックを探す
    for block in script_blocks:
        if "ruleprefix38" in block:
            return block, tmp_path

    raise ValueError(f"ページ内に ruleprefix38 テーブルが見つかりませんでした: {url}")


# ────────────────────────────────────────────────────────────────────
# データ解析
# ────────────────────────────────────────────────────────────────────


def extract_table(js_content: str, table_name: str) -> dict[int, list[int]]:
    """JS ファイルから指定テーブルのエントリを抽出する。"""
    # テーブル本体を抽出（var NAME = { ... }）
    pattern = rf"var\s+{re.escape(table_name)}\s*=\s*\{{([^}}]+)\}}"
    m = re.search(pattern, js_content, re.DOTALL)
    if not m:
        raise ValueError(f"テーブル '{table_name}' が見つかりません")
    body = m.group(1)

    # 各エントリを抽出（0xKEY: [v1, v2, ...]）
    entries: dict[int, list[int]] = {}
    entry_pattern = r"(0x[0-9a-fA-F]+)\s*:\s*\[([^\]]+)\]"
    for em in re.finditer(entry_pattern, body):
        key = int(em.group(1), 16)
        values = [int(v.strip()) for v in em.group(2).split(",")]
        entries[key] = values

    return entries


# ────────────────────────────────────────────────────────────────────
# 変換ロジック
# ────────────────────────────────────────────────────────────────────


@dataclass
class MapRuleData:
    ipv6_hextet: list[int]  # hextet[0..7] (IPv6 プレフィックス部分)
    ipv6_prefix_len: int
    ipv4_octets: list[int]  # IPv4 プレフィックス（マスク済み）4 オクテット
    ipv4_prefix_len: int
    ea_length: int
    psid_length: int
    psid_offset: int
    br_address: str


def compute_prefix31(table_name: str, key: int) -> int:
    """キーから prefix31 を計算する。"""
    if table_name == "ruleprefix31":
        return key
    else:
        # ruleprefix38 / ruleprefix38_20
        h0 = key >> 24
        h1 = (key >> 8) & 0xFFFF
        return h0 * 0x10000 + (h1 & 0xFFFE)


def determine_br_address(table_name: str, key: int, prefix31: int) -> str:
    """BR アドレスを決定する。"""
    for lo, hi, addr in BR_ADDR_CONDITIONS:
        if lo <= prefix31 < hi:
            return addr
    if table_name == "ruleprefix38_20":
        return DEFAULT_BR_ADDR
    # ruleprefix38 の大半は JS では peeraddr = false → デフォルト補完
    return DEFAULT_BR_ADDR


def key_to_ipv6_hextet(table_name: str, key: int) -> list[int]:
    """キーから IPv6 プレフィックスの hextet リスト（8 要素）を返す。"""
    hextets = [0] * 8
    if table_name == "ruleprefix31":
        # K31: hextet[0] = K31 >> 16, hextet[1] = K31 & 0xfffe
        hextets[0] = key >> 16
        hextets[1] = key & 0xFFFE
    else:
        # ruleprefix38 / ruleprefix38_20
        # K38: hextet[0] = K38 >> 24, hextet[1] = (K38 >> 8) & 0xffff
        #      hextet[2] = (K38 & 0xff) << 8
        hextets[0] = key >> 24
        hextets[1] = (key >> 8) & 0xFFFF
        hextets[2] = (key & 0xFF) << 8
    return hextets


def values_to_ipv4(table_name: str, values: list[int]) -> list[int]:
    """テーブル値から IPv4 プレフィックスの 4 オクテット（マスク済み）を返す。"""
    if table_name == "ruleprefix38":
        # 値 [a, b, c]: c & 0xFC でマスク（下位 2 ビットが可変）
        return [values[0], values[1], values[2] & 0xFC, 0]
    elif table_name == "ruleprefix31":
        # 値 [a, b]: b & 0xFE でマスク（bit0 が可変）
        return [values[0], values[1] & 0xFE, 0, 0]
    else:  # ruleprefix38_20
        # 値 [a, b, c]: c & 0xF0 でマスク（下位 4 ビットが可変）
        return [values[0], values[1], values[2] & 0xF0, 0]


def convert_entry(
    table_name: str,
    key: int,
    values: list[int],
    params: dict,
) -> MapRuleData:
    """テーブルエントリを MapRuleData に変換する。"""
    prefix31 = compute_prefix31(table_name, key)
    br_address = determine_br_address(table_name, key, prefix31)
    ipv6_hextet = key_to_ipv6_hextet(table_name, key)
    ipv4_octets = values_to_ipv4(table_name, values)

    return MapRuleData(
        ipv6_hextet=ipv6_hextet,
        ipv6_prefix_len=params["ipv6_prefix_len"],
        ipv4_octets=ipv4_octets,
        ipv4_prefix_len=params["ipv4_prefix_len"],
        ea_length=params["ea_length"],
        psid_length=params["psid_length"],
        psid_offset=params["psid_offset"],
        br_address=br_address,
    )


# ────────────────────────────────────────────────────────────────────
# 検証
# ────────────────────────────────────────────────────────────────────


def validate_table_params(params: dict, table_name: str) -> None:
    """テーブルパラメータの整合性を検証する。"""
    ipv6_prefix_len = params["ipv6_prefix_len"]
    ea_length = params["ea_length"]
    psid_length = params["psid_length"]
    psid_offset = params["psid_offset"]
    ipv4_prefix_len = params["ipv4_prefix_len"]

    # ea_length = 56 - ipv6_prefix_len
    expected_ea = 56 - ipv6_prefix_len
    assert ea_length == expected_ea, (
        f"{table_name}: ea_length={ea_length} != 56 - {ipv6_prefix_len} = {expected_ea}"
    )

    # ipv4_prefix_len = 32 - (ea_length - psid_length)
    expected_ipv4 = 32 - (ea_length - psid_length)
    assert ipv4_prefix_len == expected_ipv4, (
        f"{table_name}: ipv4_prefix_len={ipv4_prefix_len} != "
        f"32 - ({ea_length} - {psid_length}) = {expected_ipv4}"
    )

    # psid_offset + psid_length <= 16
    assert psid_offset + psid_length <= 16, (
        f"{table_name}: psid_offset({psid_offset}) + psid_length({psid_length}) > 16"
    )

    # ea_length >= psid_length
    assert ea_length >= psid_length, (
        f"{table_name}: ea_length({ea_length}) < psid_length({psid_length})"
    )

    # ipv6_prefix_len + ea_length <= 64
    assert ipv6_prefix_len + ea_length <= 64, (
        f"{table_name}: ipv6_prefix_len({ipv6_prefix_len}) + ea_length({ea_length}) > 64"
    )


def check_no_overlap_between_38_20_and_br_conditions(
    tables: dict[str, dict[int, list[int]]],
) -> None:
    """ruleprefix38_20 エントリが条件 1-3 の prefix31 範囲と重複しないことをチェックする。"""
    for key in tables.get("ruleprefix38_20", {}).keys():
        prefix31 = compute_prefix31("ruleprefix38_20", key)
        for lo, hi, addr in BR_ADDR_CONDITIONS:
            if lo <= prefix31 < hi:
                raise AssertionError(
                    f"ruleprefix38_20 エントリ (key=0x{key:x}, prefix31=0x{prefix31:x}) が "
                    f"BR 条件範囲 [0x{lo:x}, 0x{hi:x}) と重複しています。手動対処が必要です。"
                )


# ────────────────────────────────────────────────────────────────────
# Rust コード生成
# ────────────────────────────────────────────────────────────────────


def ipv6_hextet_to_new_args(hextets: list[int]) -> str:
    """hextet リストを Ipv6Addr::new(...) の引数文字列に変換する。"""
    return ", ".join(f"0x{h:04x}" for h in hextets)


def ipv4_octets_to_new_args(octets: list[int]) -> str:
    """オクテットリストを Ipv4Addr::new(...) の引数文字列に変換する。"""
    return ", ".join(str(o) for o in octets)


def br_addr_to_new_args(addr: str) -> str:
    """BR アドレス文字列を Ipv6Addr::new(...) の引数文字列に変換する。"""
    # IPv6 アドレスを展開して 8 グループの 16 進数に変換する
    import ipaddress

    ip = ipaddress.IPv6Address(addr)
    packed = ip.packed
    groups = []
    for i in range(0, 16, 2):
        groups.append((packed[i] << 8) | packed[i + 1])
    return ", ".join(f"0x{g:04x}" for g in groups)


def generate_rust_code(
    rules: list[MapRuleData],
    input_file: str,
    file_sha256: str,
) -> str:
    """MapRuleData のリストから Rust ソースコードを生成する。"""
    n = len(rules)

    lines = []
    lines.append("// このファイルは自動生成されています。直接編集しないでください。")
    lines.append(f"// 生成元: {input_file}")
    lines.append(f"// 生成元 SHA256: {file_sha256}")
    lines.append(f"// 総件数: {n}")
    lines.append("//")
    lines.append("// 更新手順:")
    lines.append(f"//   python tools/gen_v6plus_rules.py --input {input_file} \\")
    lines.append("//       --output src/map/v6plus_rules.rs")
    lines.append("")
    lines.append("use std::net::{Ipv4Addr, Ipv6Addr};")
    lines.append("")
    lines.append("use ipnet::{Ipv4Net, Ipv6Net};")
    lines.append("")
    lines.append("use crate::map::rule::{MapRule, PortParams};")
    lines.append("")
    lines.append(f"static RULES: [MapRule; {n}] = [")

    for r in rules:
        ip6_args = ipv6_hextet_to_new_args(r.ipv6_hextet)
        ip4_args = ipv4_octets_to_new_args(r.ipv4_octets)
        br_args = br_addr_to_new_args(r.br_address)
        lines.append("    MapRule {")
        lines.append(
            f"        ipv6_prefix: Ipv6Net::new_assert(Ipv6Addr::new({ip6_args}), {r.ipv6_prefix_len}),"
        )
        lines.append(
            f"        ipv4_prefix: Ipv4Net::new_assert(Ipv4Addr::new({ip4_args}), {r.ipv4_prefix_len}),"
        )
        lines.append(f"        ea_length: {r.ea_length},")
        lines.append(f"        is_fmr: true,")
        lines.append(f"        br_address: Ipv6Addr::new({br_args}),")
        lines.append(f"        port_params: PortParams {{")
        lines.append(f"            psid_offset: {r.psid_offset},")
        lines.append(f"            psid_length: {r.psid_length},")
        lines.append(f"        }},")
        lines.append("    },")

    lines.append("];")
    lines.append("")
    lines.append("/// v6プラス向け静的 MAP ルール。")
    lines.append("///")
    lines.append("/// テーブル優先順: ruleprefix38 → ruleprefix31 → ruleprefix38_20。")
    lines.append("/// 各テーブル内はキー昇順（数値昇順）で固定。")
    lines.append("pub static V6PLUS_MAP_RULES: &[MapRule] = &RULES;")
    lines.append("")
    lines.append(f"pub const RULE_COUNT: usize = {n};")
    lines.append("")
    lines.append("const _: () = assert!(V6PLUS_MAP_RULES.len() == RULE_COUNT);")
    lines.append("")

    return "\n".join(lines)


# ────────────────────────────────────────────────────────────────────
# メイン
# ────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="v6plus MAP ルール生成スクリプト")
    parser.add_argument(
        "--input",
        help="入力 JS ファイルパス（省略時は --url から自動取得）",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"取得元 HTML URL（--input 省略時に使用、デフォルト: {DEFAULT_URL}）",
    )
    parser.add_argument("--output", required=True, help="出力 Rust ファイルパス")
    args = parser.parse_args()

    if args.input:
        # 既存動作: ローカルファイルから読み込み
        with open(args.input, "r", encoding="utf-8") as f:
            js_content = f.read()
        input_label = args.input
    else:
        # URL から HTML を取得して JS を抽出
        print(f"取得中: {args.url}", file=sys.stderr)
        js_content, tmp_path = fetch_and_extract_js(args.url)
        print(f"HTML を一時保存: {tmp_path}", file=sys.stderr)
        input_label = args.url

    # SHA256 計算
    file_sha256 = hashlib.sha256(js_content.encode("utf-8")).hexdigest()

    # テーブルパラメータ検証
    for table_name, params in TABLE_PARAMS.items():
        validate_table_params(params, table_name)

    # テーブル抽出
    tables: dict[str, dict[int, list[int]]] = {}
    for table_name in TABLE_ORDER:
        tables[table_name] = extract_table(js_content, table_name)
        print(
            f"{table_name}: {len(tables[table_name])} エントリ",
            file=sys.stderr,
        )

    # ruleprefix38_20 と BR 条件の重複チェック
    check_no_overlap_between_38_20_and_br_conditions(tables)

    # MapRuleData に変換（テーブル優先順 × キー昇順）
    all_rules: list[MapRuleData] = []
    for table_name in TABLE_ORDER:
        params = TABLE_PARAMS[table_name]
        for key in sorted(tables[table_name].keys()):
            values = tables[table_name][key]
            rule = convert_entry(table_name, key, values, params)
            all_rules.append(rule)

    if len(all_rules) == 0:
        print(
            "エラー: ルールが 0 件です。入力ファイルを確認してください。",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"合計: {len(all_rules)} エントリ", file=sys.stderr)

    # Rust コード生成
    rust_code = generate_rust_code(all_rules, input_label, file_sha256)

    # 出力ファイル書き込み
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(rust_code)

    print(f"生成完了: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
