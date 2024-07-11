//! An estimator to analyse the security of different LPN parameters.
//! The implementation is according to https://eprint.iacr.org/2022/712.pdf.

use rug::{ops::Pow, Float};

// The precision for security analysis.
const PRECISION: u32 = 200;

// The highest security level in our analysis.
const HIGHEST_SECURITY: usize = 256;

/// Define the struct of LPN estimator.
pub struct LpnEstimator;

impl LpnEstimator {
    // Compute the combination number of n choose m.
    fn cal_comb(n: usize, m: usize) -> Float {
        assert!(n >= m);

        let mut res = Float::with_val(PRECISION, 1);

        let range = std::cmp::min(m, n - m);
        for i in 0..range {
            res *= Float::with_val(PRECISION, (n - i) as f64)
                / Float::with_val(PRECISION, (range - i) as f64);
        }

        res
    }

    /// Compute the bit security under the Pooled Gauss attack, see page 37 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    pub fn security_under_pooled_gauss_binary(n: usize, k: usize, t: usize) -> f64 {
        let log_guess_prob = Self::cal_comb(n - k, t).log2() - Self::cal_comb(n, t).log2();

        let matrix_inversion_cost = (std::cmp::min(n - k, k) as f64).powf(2.8);

        matrix_inversion_cost.log2() - log_guess_prob.to_f64()
    }

    // Compute the fomulas inside the min function of Therem 14 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    fn sub_sd_isd_binary(n: usize, k: usize, t: usize, l: usize, p: usize) -> f64 {
        let l_zero = Self::cal_comb((k + l) / 2 + 1, p / 2);

        let log_l_zero = l_zero.clone().log2();
        let log_s: Float = 2 * log_l_zero.clone() - l;

        // If it has enough security, just break.
        if log_l_zero > HIGHEST_SECURITY || log_s > HIGHEST_SECURITY {
            return HIGHEST_SECURITY as f64;
        }

        // Computes s = 1 << log_s.
        let s = Float::with_val(PRECISION, 2).pow(log_s.clone());

        // Compute T_Gauss + 2 * L0 * N + 2 * |S| * N
        let mut cost = Float::with_val(PRECISION, (n - k - l) * (n - k))
            / Float::with_val(PRECISION, f64::log2((n - k - l) as f64));

        cost += 2 * l_zero + 2 * s;
        cost *= n;

        // Compute log P(p,l).
        let mut log_p = Self::cal_comb(n - k - l, t - p).log2() - Self::cal_comb(n, t).log2();

        log_p += l + log_s;

        (cost.log2() - log_p).to_f64()
    }

    // Minimize sub_SD_ISD_binary when fix p.
    fn min_sub_sd_isd_binary_with_fixed_p(n: usize, k: usize, t: usize, p: usize) -> f64 {
        let mut start = 1;
        let mut end = n - k;

        let t_start = Self::sub_sd_isd_binary(n, k, t, start, p);
        let mut res = t_start;

        while end - start > 30 {
            let mid_left = (end - start) / 3 + start;
            let mid_right = end - (end - start) / 3;

            let left = Self::sub_sd_isd_binary(n, k, t, mid_left, p);
            let right = Self::sub_sd_isd_binary(n, k, t, mid_right, p);

            if left > right {
                start = mid_left;
                res = right;
            } else {
                end = mid_right;
                res = left;
            }
        }

        for l in start..=end {
            let t = Self::sub_sd_isd_binary(n, k, t, l, p);
            if t <= res {
                res = t;
            }
        }

        res
    }

    /// The security of the lpn parameters under SD_ISD attack for binary field. See Therem 14 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    pub fn security_under_sd_isd_binary(n: usize, k: usize, t: usize) -> f64 {
        let mut res = Self::sub_sd_isd_binary(n, k, t, 0, 0);

        for p in 0..t / 2 {
            let min = Self::min_sub_sd_isd_binary_with_fixed_p(n, k, t, p);
            if min <= res {
                res = min;
            }
            if min > res + 30.0 {
                break;
            }
        }

        res
    }
}

mod tests {
    #[test]
    fn security_test() {
        let security = crate::LpnEstimator::security_under_sd_isd_binary(1 << 14, 3482, 198);
        println!("{:?}", security);
    }
}
