//! L4 チェックサム更新ヘルパー。

use aya_ebpf::{bindings::BPF_F_PSEUDO_HDR, programs::TcContext};

/// TCP/UDP チェックサムを更新する（pseudo header あり）。
///
/// `offset`: チェックサムフィールドのパケット先頭からのバイトオフセット
#[inline(always)]
pub fn update_tcp_udp_csum(
    ctx: &TcContext,
    csum_offset: usize,
    old_val: u16,
    new_val: u16,
) -> Result<(), i64> {
    ctx.l4_csum_replace(
        csum_offset,
        old_val as u64,
        new_val as u64,
        2 | (BPF_F_PSEUDO_HDR as u64),
    )
    .map_err(|e| e as i64)
}

/// ICMP チェックサムを更新する（pseudo header なし）。
///
/// `offset`: チェックサムフィールドのパケット先頭からのバイトオフセット
#[inline(always)]
pub fn update_icmp_csum(
    ctx: &TcContext,
    csum_offset: usize,
    old_val: u16,
    new_val: u16,
) -> Result<(), i64> {
    ctx.l4_csum_replace(csum_offset, old_val as u64, new_val as u64, 2)
        .map_err(|e| e as i64)
}
