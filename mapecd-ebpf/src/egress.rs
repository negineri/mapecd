//! TC BPF egress プログラム: staging_port → psid_port 変換。
//!
//! clsact qdisc の egress フックにアタッチする。
//! ip6tnl0 の TC egress は内側 IPv4 パケットを処理する。
//!
//! # 変換アルゴリズム（全単射）
//!
//! ```text
//! idx      = staging_val - staging_min
//! R        = (idx >> block_shift) + 1
//! j        = idx & ((1 << block_shift) - 1)
//! psid_val = R * (1 << (16 - offset)) + psid * (1 << block_shift) + j
//! ```

use aya_ebpf::{macros::classifier, programs::TcContext};
use aya_ebpf::bindings::TC_ACT_OK;

use crate::{CONFIG_MAP, checksum};

// IPv4 プロトコル番号
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;

// ICMP タイプ
const ICMP_ECHO_REQUEST: u8 = 8;

// IPv4 固定ヘッダフィールドオフセット
const IPV4_IHL_OFFSET: usize = 0;
const IPV4_PROTO_OFFSET: usize = 9;

// TCP/UDP src_port オフセット（L4 ヘッダ先頭から）
const L4_SRC_PORT_OFFSET: usize = 0;
// ICMP type オフセット（L4 ヘッダ先頭から）
const ICMP_TYPE_OFFSET: usize = 0;
// ICMP checksum オフセット（L4 ヘッダ先頭から）
const ICMP_CSUM_OFFSET: usize = 2;
// ICMP identifier オフセット（L4 ヘッダ先頭から）
const ICMP_ID_OFFSET: usize = 4;

#[classifier]
pub fn tc_egress(mut ctx: TcContext) -> i32 {
    match try_egress(&mut ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_egress(ctx: &mut TcContext) -> Result<i32, ()> {
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

    // staging_val と各フィールドオフセットを取得
    let (staging_val, port_pkt_offset, csum_pkt_offset, is_icmp) = match proto {
        IPPROTO_TCP | IPPROTO_UDP => {
            let src_off = l4_offset + L4_SRC_PORT_OFFSET;
            let staging: u16 = ctx.load(src_off).map_err(|_| ())?;
            // TCP checksum: TCP=l4+16, UDP=l4+6
            let csum_off = if proto == IPPROTO_TCP {
                l4_offset + 16
            } else {
                l4_offset + 6
            };
            (staging, src_off, csum_off, false)
        }
        IPPROTO_ICMP => {
            let type_byte: u8 = ctx.load(l4_offset + ICMP_TYPE_OFFSET).map_err(|_| ())?;
            if type_byte != ICMP_ECHO_REQUEST {
                return Ok(TC_ACT_OK as i32);
            }
            let id_off = l4_offset + ICMP_ID_OFFSET;
            let staging: u16 = ctx.load(id_off).map_err(|_| ())?;
            let csum_off = l4_offset + ICMP_CSUM_OFFSET;
            (staging, id_off, csum_off, true)
        }
        _ => return Ok(TC_ACT_OK as i32),
    };

    // staging range 外はスルー
    if staging_val < cfg.staging_min || staging_val > cfg.staging_max {
        return Ok(TC_ACT_OK as i32);
    }

    // 全単射計算: staging_val → psid_val
    let block_shift = cfg.block_shift as u16;
    let block_mask = (1u16 << block_shift).wrapping_sub(1);

    let idx = staging_val - cfg.staging_min;
    let r = (idx >> block_shift) + 1;
    let j = idx & block_mask;
    let psid_val = (r << (16 - cfg.offset as u16))
        + (cfg.psid << block_shift)
        + j;

    // フィールド書き換え
    ctx.store(port_pkt_offset, &psid_val, 0).map_err(|_| ())?;

    // チェックサム更新
    if is_icmp {
        let _ = checksum::update_icmp_csum(ctx, csum_pkt_offset, staging_val, psid_val);
    } else {
        let _ = checksum::update_tcp_udp_csum(ctx, csum_pkt_offset, staging_val, psid_val);
    }

    Ok(TC_ACT_OK as i32)
}
