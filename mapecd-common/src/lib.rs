//! mapecd-common: eBPF カーネル側とユーザースペース側で共有する型定義。
//!
//! `#![no_std]` で定義することで BPF クレート（`bpfel-unknown-none` ターゲット）
//! からも参照できる。

#![no_std]

/// BPF CONFIG_MAP に格納する PSID 変換パラメータ。
///
/// ユーザースペース側（`EbpfManager`）が計算して書き込み、
/// BPF プログラム（egress / ingress）が読み出す。
///
/// # フィールド計算（a = offset, k = length）
///
/// - `block_shift` = `16 - a - k`
/// - `staging_min`  = `1 << (16 - a)` （a=0 特殊: 1）
/// - `staging_max`  = `staging_min + (2^a - 1) * 2^(16-a-k) - 1` （a=0 特殊: 65535）
///
/// # a=0 特殊ケース
///
/// a=0 の場合は R 次元が存在せずポート変換は不要。
/// BPF プログラムは `offset == 0` を検出して TC_ACT_OK でスルーする。
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PsidConfig {
    /// a: psid_offset（除外ビット数）
    pub offset: u8,
    /// k: psid_length（PSID ビット幅）
    pub length: u8,
    /// `16 - offset - length`（BPF 内シフト量。事前計算して格納）
    pub block_shift: u8,
    /// アライメントパディング
    pub _pad: u8,
    /// PSID 値
    pub psid: u16,
    /// staging range 最小ポート（= `1 << (16 - offset)`、a=0 は 1）
    pub staging_min: u16,
    /// staging range 最大ポート（a=0 は 65535）
    pub staging_max: u16,
}

impl PsidConfig {
    /// MAP-E パラメータから `PsidConfig` を生成する。
    ///
    /// # エラー
    ///
    /// `offset + length > 16` の場合は `None` を返す。
    pub fn try_new(offset: u8, length: u8, psid: u16) -> Option<Self> {
        if (offset as u16) + (length as u16) > 16 {
            return None;
        }

        if offset == 0 {
            // a=0: R 次元なし。ポート変換は不要だが staging range は全範囲。
            return Some(Self {
                offset: 0,
                length,
                block_shift: 0,
                _pad: 0,
                psid,
                staging_min: 1,
                staging_max: 65535,
            });
        }

        // block_shift = 16 - a - k
        let block_shift = 16u8.saturating_sub(offset).saturating_sub(length);
        // staging_min = 1 << (16 - a)
        let staging_min: u16 = 1u16 << (16 - offset as u16);
        // num_r_blocks = 2^a - 1
        let num_r_blocks: u32 = (1u32 << offset) - 1;
        // block_size = 2^block_shift
        let block_size: u32 = 1u32 << block_shift;
        // staging_max = staging_min + num_r_blocks * block_size - 1
        let total_ports: u32 = num_r_blocks * block_size;
        let staging_max: u16 = (staging_min as u32 + total_ports - 1) as u16;

        Some(Self {
            offset,
            length,
            block_shift,
            _pad: 0,
            psid,
            staging_min,
            staging_max,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_psid_config_size() {
        // 8 バイト: u8×4 + u16×3 = 4 + 6 = 10... ただし #[repr(C)] のアライメント考慮
        // offset(1) + length(1) + block_shift(1) + _pad(1) + psid(2) + staging_min(2) + staging_max(2) = 10
        // repr(C) では u16 が 2 バイトアライン → 全体 10 バイト
        assert_eq!(mem::size_of::<PsidConfig>(), 10);
    }

    #[test]
    fn test_try_new_v6plus_a4_k8() {
        // v6plus: a=4, k=8, PSID=5
        let cfg = PsidConfig::try_new(4, 8, 5).unwrap();
        assert_eq!(cfg.offset, 4);
        assert_eq!(cfg.length, 8);
        assert_eq!(cfg.block_shift, 4); // 16 - 4 - 8 = 4
        assert_eq!(cfg.psid, 5);
        assert_eq!(cfg.staging_min, 4096); // 1 << 12
        // num_r_blocks = 15, block_size = 16, total = 240
        assert_eq!(cfg.staging_max, 4335); // 4096 + 240 - 1
    }

    #[test]
    fn test_try_new_a0() {
        let cfg = PsidConfig::try_new(0, 0, 0).unwrap();
        assert_eq!(cfg.offset, 0);
        assert_eq!(cfg.staging_min, 1);
        assert_eq!(cfg.staging_max, 65535);
        assert_eq!(cfg.block_shift, 0);
    }

    #[test]
    fn test_try_new_invalid_overflow() {
        // offset + length > 16 はエラー
        assert!(PsidConfig::try_new(10, 8, 0).is_none());
        assert!(PsidConfig::try_new(16, 1, 0).is_none());
    }

    #[test]
    fn test_try_new_boundary_a_plus_k_eq_16() {
        // offset + length = 16 は有効
        let cfg = PsidConfig::try_new(4, 12, 0);
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.block_shift, 0); // 16 - 4 - 12 = 0
    }
}
