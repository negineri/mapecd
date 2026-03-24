use std::ops::RangeInclusive;

use super::{MapeError, MapeRule};

/// ポートセット計算結果
#[derive(Debug, Clone)]
pub struct PortSet {
    /// PSID オフセット
    pub offset: u8,
    /// PSID 長
    pub psid_len: u8,
    /// PSID 値
    pub psid: u16,
    /// 使用可能なポートレンジのリスト
    pub ranges: Vec<RangeInclusive<u16>>,
}

impl PortSet {
    /// MAP-E ルールからポートセットを計算する（RFC 7597 Section 5.1）
    ///
    /// ポートレンジ = PSID オフセットビット + PSID + ランダムビット
    pub fn from_rule(rule: &MapeRule) -> Result<Self, MapeError> {
        let offset = rule.psid_offset();
        let psid_len = rule.psid_len();
        let psid = rule.psid();

        if psid_len > 0 && psid >= (1 << psid_len) {
            return Err(MapeError::InvalidPsid { psid, psid_len });
        }

        let mut ranges = Vec::new();

        if psid_len == 0 {
            // PSID なし：全ポートが使用可能（ただし 0-1023 は除外）
            ranges.push(1024..=65535);
            return Ok(Self { offset, psid_len, psid, ranges });
        }

        // ポートビット数 = 16 - offset - psid_len
        let random_bits = 16u8.saturating_sub(offset).saturating_sub(psid_len);

        for r in 0..(1u32 << random_bits) {
            // port = [offset bits][psid bits][random bits]
            // offset 部分は 1 から始まる（ウェルノウンポート回避）
            for a in 1..(1u32 << offset) {
                let port = (a << (psid_len + random_bits))
                    | ((psid as u32) << random_bits)
                    | r;

                if port > 0 && port <= 65535 {
                    let p = port as u16;
                    // 連続するポートをレンジにまとめる
                    if let Some(last) = ranges.last_mut() {
                        if *last.end() + 1 == p {
                            *last = *last.start()..=p;
                            continue;
                        }
                    }
                    ranges.push(p..=p);
                }
            }
        }

        Ok(Self { offset, psid_len, psid, ranges })
    }

    /// 使用可能な総ポート数を返す
    pub fn total_ports(&self) -> usize {
        self.ranges.iter().map(|r| (r.end() - r.start() + 1) as usize).sum()
    }
}
