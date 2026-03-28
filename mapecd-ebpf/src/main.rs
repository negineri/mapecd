#![no_std]
#![no_main]

mod checksum;
mod egress;
mod ingress;

use aya_ebpf::{macros::map, maps::Array};
use mapecd_common::PsidConfig;

/// PSID 変換設定マップ（1 エントリ）。
/// ユーザースペース側（EbpfManager）が書き込み、egress/ingress プログラムが読み出す。
#[map]
static CONFIG_MAP: Array<PsidConfig> = Array::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
