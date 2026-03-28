//! TC BPF ingress プログラム: psid_port → staging_port 逆変換。
//!
//! clsact qdisc の ingress フックにアタッチする。
//! ip6tnl0 の TC ingress はデカプセル後の内側 IPv4 パケットを処理する。
//!
//! # 逆変換アルゴリズム（全単射の逆）
//!
//! ```text
//! j            = psid_val & ((1 << block_shift) - 1)
//! R            = psid_val >> (16 - offset)
//! idx          = ((R - 1) << block_shift) | j
//! staging_val  = staging_min + idx
//! ```

use aya_ebpf::{macros::classifier, programs::TcContext};
use aya_ebpf::bindings::TC_ACT_OK;

use crate::{CONFIG_MAP, checksum};

// IPv4 プロトコル番号
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// ICMP タイプ
const ICMP_ECHO_REPLY: u8 = 0;

// IPv4 固定ヘッダフィールドオフセット
const IPV4_IHL_OFFSET: usize = 0;
const IPV4_PROTO_OFFSET: usize = 9;

// TCP/UDP dst_port オフセット（L4 ヘッダ先頭から）
const L4_DST_PORT_OFFSET: usize = 2;
// ICMP type オフセット（L4 ヘッダ先頭から）
const ICMP_TYPE_OFFSET: usize = 0;
// ICMP checksum オフセット（L4 ヘッダ先頭から）
const ICMP_CSUM_OFFSET: usize = 2;
// ICMP identifier オフセット（L4 ヘッダ先頭から）
const ICMP_ID_OFFSET: usize = 4;

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    match try_ingress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
    // IHL を読んで L4 オフセットを計算（IPv4 ヘッダオプション対応）
    let ihl_byte: u8 = ctx.load(IPV4_IHL_OFFSET).map_err(|_| ())?;
    let ihl = (ihl_byte & 0x0f) as usize;
    let l4_offset = ihl * 4;

    let proto: u8 = ctx.load(IPV4_PROTO_OFFSET).map_err(|_| ())?;

    // CONFIG_MAP からパラメータ取得
    let cfg = match CONFIG_MAP.get(0) {
        Some(c) => *c,
        None => return Ok(TC_ACT_OK as i32),
    };

    // offset=0 は変換不要（R 次元なし）
    if cfg.offset == 0 {
        return Ok(TC_ACT_OK as i32);
    }

    // psid_val と各フィールドオフセットを取得
    let (psid_val, port_pkt_offset, csum_pkt_offset, is_icmp) = match proto {
        IPPROTO_TCP | IPPROTO_UDP => {
            let dst_off = l4_offset + L4_DST_PORT_OFFSET;
            let psid: u16 = ctx.load(dst_off).map_err(|_| ())?;
            let csum_off = if proto == IPPROTO_TCP {
                l4_offset + 16
            } else {
                l4_offset + 6
            };
            (psid, dst_off, csum_off, false)
        }
        IPPROTO_ICMP => {
            let type_byte: u8 = ctx.load(l4_offset + ICMP_TYPE_OFFSET).map_err(|_| ())?;
            if type_byte != ICMP_ECHO_REPLY {
                return Ok(TC_ACT_OK as i32);
            }
            let id_off = l4_offset + ICMP_ID_OFFSET;
            let psid: u16 = ctx.load(id_off).map_err(|_| ())?;
            let csum_off = l4_offset + ICMP_CSUM_OFFSET;
            (psid, id_off, csum_off, true)
        }
        _ => return Ok(TC_ACT_OK as i32),
    };

    let block_shift = cfg.block_shift as u16;
    let block_mask = (1u16 << block_shift).wrapping_sub(1);

    // R 検証: R=0 は未割り当てブロック
    let r = psid_val >> (16 - cfg.offset as u16);
    if r == 0 {
        return Ok(TC_ACT_OK as i32);
    }

    // PSID ビット検証: 自 CE の PSID に属するか確認
    let psid_bits = (psid_val >> block_shift) & ((1u16 << cfg.length) - 1);
    if psid_bits != cfg.psid {
        return Ok(TC_ACT_OK as i32);
    }

    // 全単射逆計算: psid_val → staging_val
    let j = psid_val & block_mask;
    let idx = ((r - 1) << block_shift) | j;
    let staging_val = cfg.staging_min + idx;

    // フィールド書き換え
    ctx.store(port_pkt_offset, &staging_val, 0).map_err(|_| ())?;

    // チェックサム更新
    if is_icmp {
        let _ = checksum::update_icmp_csum(ctx, csum_pkt_offset, psid_val, staging_val);
    } else {
        let _ = checksum::update_tcp_udp_csum(ctx, csum_pkt_offset, psid_val, staging_val);
    }

    Ok(TC_ACT_OK as i32)
}
