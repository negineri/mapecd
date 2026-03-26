use std::ops::RangeInclusive;

use super::rule::PortParams;

/// CE に割り当てられたポート範囲を計算する（RFC 7597 Section 5.1）。
///
/// ポート計算式:
/// ```text
/// Port(R, j) = R * 2^(a+k) + j * 2^k + PSID
/// ```
/// - R ∈ [1, 2^(16-a-k) - 1]
/// - j ∈ [0, 2^a - 1]
///
/// ## `a=0, k=0` のケース（OPTION_S46_PORTPARAMS 省略デフォルト）
///
/// - k=0 のため PSID は 0 ビット幅 → PSID=0 が自明。
/// - j の範囲は [0, 2^0-1] = {0} のみ。
/// - Port(R, 0) = R * 2^0 + 0 + 0 = R。
/// - R ∈ [1, 65535] の各ポートが連続するため、ポストプロセスの
///   range 結合により `vec![1..=65535]` の単一レンジにまとめられる。
/// - 呼び出し元は `a=0, k=0` を特別扱いせずそのまま nftables の
///   port_ranges セットに渡す。
pub fn calc_port_ranges(port_params: &PortParams, psid: u16) -> Vec<RangeInclusive<u16>> {
    let a = port_params.psid_offset as u32;
    let k = port_params.psid_length as u32;

    // R の最大値: 2^(16-a-k) - 1
    let r_count = 1u32 << (16 - a - k); // 2^(16-a-k), R は 1..r_count
    // j の個数: 2^a
    let j_count = 1u32 << a;

    let capacity = (r_count as usize).saturating_sub(1) * j_count as usize;
    let mut ports: Vec<u16> = Vec::with_capacity(capacity);

    for r in 1..r_count {
        for j in 0..j_count {
            // Port(R, j) = R * 2^(a+k) + j * 2^k + PSID
            let port = r * (1 << (a + k)) + j * (1 << k) + psid as u32;
            ports.push(port as u16);
        }
    }

    // ポートは R が増えるごとに単調増加するため既にソート済み。
    // 隣接するポートを RangeInclusive に結合するポストプロセス。
    let mut merged: Vec<RangeInclusive<u16>> = Vec::new();

    let Some(&first) = ports.first() else {
        return merged;
    };

    let mut start = first;
    let mut end = first;

    for &port in ports.iter().skip(1) {
        if end.checked_add(1) == Some(port) {
            end = port;
        } else {
            merged.push(start..=end);
            start = port;
            end = port;
        }
    }
    merged.push(start..=end);

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::rule::PortParams;

    fn params(psid_offset: u8, psid_length: u8) -> PortParams {
        PortParams {
            psid_offset,
            psid_length,
        }
    }

    // ----------------------------------------------------------------
    // a=0, k=0: 全ポート [1..=65535] に結合されること
    // ----------------------------------------------------------------

    #[test]
    fn test_a0_k0_all_ports() {
        let ranges = calc_port_ranges(&params(0, 0), 0);
        assert_eq!(ranges, vec![1u16..=65535u16]);
    }

    // ----------------------------------------------------------------
    // v6plus 固有値 (a=4, k=8, PSID=5): 総数 240 ポート
    // ----------------------------------------------------------------

    #[test]
    fn test_v6plus_total_port_count() {
        let ranges = calc_port_ranges(&params(4, 8), 5);
        let total: usize = ranges
            .iter()
            .map(|r| (*r.end() - *r.start()) as usize + 1)
            .sum();
        assert_eq!(total, 240, "v6plus PSID=5 の総ポート数は 240");
    }

    #[test]
    fn test_v6plus_port_formula() {
        // v6plus: Port(R, j) = R*4096 + j*256 + PSID
        // R=1, j=0: 4096 + 0 + 5 = 4101
        // R=1, j=1: 4096 + 256 + 5 = 4357
        // R=15, j=15: 15*4096 + 15*256 + 5 = 61440 + 3840 + 5 = 65285
        let ranges = calc_port_ranges(&params(4, 8), 5);

        let all_ports: Vec<u16> = ranges
            .iter()
            .flat_map(|r| r.clone())
            .collect();

        assert!(all_ports.contains(&4101), "Port(1,0) = 4101 が含まれること");
        assert!(all_ports.contains(&4357), "Port(1,1) = 4357 が含まれること");
        assert!(all_ports.contains(&65285), "Port(15,15) = 65285 が含まれること");
    }

    // ----------------------------------------------------------------
    // a=0 エッジケース: Port(R, 0) = R * 2^k + PSID となること
    // ----------------------------------------------------------------

    #[test]
    fn test_a0_port_formula() {
        // a=0, k=8, PSID=5: Port(R, 0) = R * 256 + 5
        // R=1: 261, R=2: 517, ...
        let ranges = calc_port_ranges(&params(0, 8), 5);
        let all_ports: Vec<u16> = ranges.iter().flat_map(|r| r.clone()).collect();

        assert!(all_ports.contains(&261), "Port(1,0) = 261 が含まれること");
        assert!(all_ports.contains(&517), "Port(2,0) = 517 が含まれること");
    }

    // ----------------------------------------------------------------
    // 隣接ポートのマージ確認
    // ----------------------------------------------------------------

    #[test]
    fn test_merge_adjacent_ranges() {
        // a=4, k=0, PSID=0: Port(R, j) = R*16 + j (k=0 なので PSID=0)
        // R=1, j=0..15: ports 16..=31 (連続)
        // R=2, j=0..15: ports 32..=47 (連続 & 前の末尾と隣接)
        // → [16..=4095*16+15] にマージされる (R=1..4095)
        // ただし R_max = 2^(16-4-0) - 1 = 4095, R*16+15 の最大 = 4095*16+15 = 65535
        let ranges = calc_port_ranges(&params(4, 0), 0);
        // 全ポートが [16..=65535] に結合されるはず
        assert_eq!(ranges, vec![16u16..=65535u16]);
    }
}
