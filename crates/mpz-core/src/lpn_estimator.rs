//! An estimator to analyse the security of different LPN parameters.
//! The implementation is according to https://eprint.iacr.org/2022/712.pdf.

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rug::{ops::Pow, Float};

// The precision for security analysis.
const PRECISION: u32 = 200;

// The highest security level.
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

    /// Compute the bit security under the Pooled Gauss attack, see page 37 in this [paper](https://eprint.iacr.org/2022/712.pdf). Note that it is the same for binary and larger fields.
    ///
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_under_pooled_gauss(n: usize, k: usize, t: usize) -> f64 {
        let log_guess_prob = Self::cal_comb(n - k, t).log2() - Self::cal_comb(n, t).log2();

        let matrix_inversion_cost = (std::cmp::min(n - k, k) as f64).powf(2.8);

        matrix_inversion_cost.log2() - log_guess_prob.to_f64()
    }

    // Compute the fomulas inside the min function of Theorem 14 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    fn sub_sd_isd_binary(n: usize, k: usize, t: usize, l: usize, p: usize) -> f64 {
        let l_zero = Self::cal_comb((k + l) / 2 + 1, p / 2);

        let log_l_zero = l_zero.clone().log2();
        let log_s: Float = 2 * log_l_zero.clone() - l;

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

    // Minimize sub_sd_isd_binary when fix p.
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
    ///
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_under_sd_isd_binary(n: usize, k: usize, t: usize) -> f64 {
        let mut res = Self::sub_sd_isd_binary(n, k, t, 0, 0);

        for p in 0..t / 2 {
            let min = Self::min_sub_sd_isd_binary_with_fixed_p(n, k, t, p);
            if min <= res {
                res = min;
            }
        }
        res
    }

    // Compute the fomulas inside the min function of Theorem 16 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    #[allow(clippy::too_many_arguments)]
    fn sub_bjmm_isd_binary(
        n: usize,
        k: usize,
        t: usize,
        p2: usize,
        l: usize,
        e1: usize,
        e2: usize,
        r1: usize,
        r2: usize,
        local_min: f64,
    ) -> f64 {
        assert!(p2 >= e2);
        let p1 = 2 * (p2 - e2);
        assert!(p1 >= e1);
        let p = 2 * (p1 - e1);

        let s3 = Self::cal_comb((k + l) / 2 + 1, p2 / 2);

        let log_s3 = s3.clone().log2();
        let log_c3: Float = s3.clone().log2() * 2 - r2;
        let c3 = Float::with_val(PRECISION, 2).pow(log_c3.clone());

        let log_c2: Float = log_c3.clone() * 2 - r1;
        let c2 = Float::with_val(PRECISION, 2).pow(log_c2.clone());

        assert!(k + l >= p2);
        assert!(p2 >= e2);
        let log_mu2 = Self::cal_comb(p2, e2).log2() + Self::cal_comb(k + l - p2, p2 - e2).log2()
            - Self::cal_comb(k + l, p2).log2();

        let log_s1_left = log_mu2 + log_c2.clone();
        let log_s1_right = Self::cal_comb(k + l, p1).log2() - (r1 + r2);
        let log_s1 = log_s1_left.min(&log_s1_right);

        let log_c1: Float = log_s1 * 2 - l + r1 + r2;
        let c1 = Float::with_val(PRECISION, 2).pow(log_c1.clone());

        assert!(k + l >= p1);
        assert!(p1 >= e1);
        let log_mu1 = Self::cal_comb(p1, e1).log2() + Self::cal_comb(k + l - p1, p1 - e1).log2()
            - Self::cal_comb(k + l, p1).log2();

        let log_s_left = log_mu1 + log_c1;
        let log_s_right = Self::cal_comb(k + l, p).log2() - l;

        let log_s = log_s_left.clone().min(&log_s_right);

        // Quick break
        if (log_s3.to_f64() > local_min) || (log_c3.to_f64() > local_min) || (log_c2 > local_min) {
            return HIGHEST_SECURITY as f64;
        }

        // Compute T_Gauss + (8*S3 + 4*C3 + 2*C2 + 2*C1) * N
        let mut cost = Float::with_val(PRECISION, (n - k - l) * (n - k))
            / Float::with_val(PRECISION, f64::log2((n - k - l) as f64));

        cost += 8 * s3 + 4 * c3 + 2 * c2 + 2 * c1;
        cost *= n;

        // Compute log P(p,l).
        assert!(n >= k + l);
        assert!(t >= p);
        let mut log_p = Self::cal_comb(n - k - l, t - p).log2() - Self::cal_comb(n, t).log2();

        log_p += l + log_s;

        // Quick break, the probability should be smaller than 1.
        if log_p >= 0 {
            return HIGHEST_SECURITY as f64;
        }

        (cost.log2() - log_p).to_f64()
    }

    // Minimize sub_bjmm_isd_binary with fixed p2 and l.
    fn min_sub_bjmm_isd_binary_with_fixed_p2_and_l(
        n: usize,
        k: usize,
        t: usize,
        p2: usize,
        l: usize,
    ) -> f64 {
        let mut local_min = HIGHEST_SECURITY as f64;
        // Try all possible values of e2.
        for e2 in 0..p2 {
            let p1 = 2 * (p2 - e2);

            let e1_start = if p1 <= (t / 2) { 0 } else { p1 - t / 2 };

            // Try all possible values of e1.
            for e1 in e1_start..p1 {
                let p = 2 * (p1 - e1);

                // The following part is according to Equation (6), Page 11 in this [paper](https://eprint.iacr.org/2013/162.pdf).
                assert!(k + l >= p2);
                assert!(k + l >= p1);
                assert!(p2 >= e2);
                assert!(p1 >= e1);
                // Proposition 1 in this [paper](https://eprint.iacr.org/2013/162.pdf).
                let log_mu2 = Self::cal_comb(p2, e2).log2()
                    + Self::cal_comb(k + l - p2, p2 - e2).log2()
                    - Self::cal_comb(k + l, p2).log2();

                let r2: Float = log_mu2 + 4 * (Self::cal_comb((k + l) / 2, p2 / 2).log2())
                    - Self::cal_comb(k + l, p1).log2();

                let r2: usize = if r2 <= 0 {
                    0
                } else if r2 >= l {
                    l - 1
                } else {
                    r2.to_f64() as usize
                };

                // Also use the equation of mu_1 in Proposition 1.
                let r = Self::cal_comb(p1, e1).log2()
                    + Self::cal_comb(k + l - p1, p1 - e1).log2()
                    + Self::cal_comb(k + l, p1).log2()
                    - Self::cal_comb(k + l, p).log2();

                let r1 = r - r2;
                let r1 = if r1 <= 0 {
                    0
                } else if (r1.clone() + r2) >= l {
                    l - r2 - 1
                } else {
                    r1.to_f64() as usize
                };

                let middle = Self::sub_bjmm_isd_binary(n, k, t, p2, l, e1, e2, r1, r2, local_min);

                if middle < local_min {
                    local_min = middle;
                }
            }
        }
        local_min
    }

    // Minimize sub_bjmm_isd_binary with fixed p2.
    fn min_sub_bjmm_isd_binary_with_fixed_p2(n: usize, k: usize, t: usize, p2: usize) -> f64 {
        let mut start = 1;
        let mut end = (n - k - 2) / 8;

        let mut min_cost = Self::min_sub_bjmm_isd_binary_with_fixed_p2_and_l(n, k, t, p2, start);

        while end - start > 10 {
            let left = (end - start) / 3 + start;
            let right = end - (end - start) / 3;

            let min_left = Self::min_sub_bjmm_isd_binary_with_fixed_p2_and_l(n, k, t, p2, left);
            let min_right = Self::min_sub_bjmm_isd_binary_with_fixed_p2_and_l(n, k, t, p2, right);

            if min_left > min_right {
                start = left;
                min_cost = min_right;
            } else {
                end = right;
                min_cost = min_left;
            }
        }

        for l in (start + 1)..(end + 5) {
            let min_middle = Self::min_sub_bjmm_isd_binary_with_fixed_p2_and_l(n, k, t, p2, l);
            if min_middle < min_cost {
                min_cost = min_middle;
            }
        }
        min_cost
    }

    /// The security of the lpn parameters under BJMM_ISD attack for binary field. See Therem 16 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    ///
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_under_bjmm_isd_binary(n: usize, k: usize, t: usize) -> f64 {
        let mut res = Self::min_sub_bjmm_isd_binary_with_fixed_p2(n, k, t, 0);

        for p2 in 1..t {
            let min = Self::min_sub_bjmm_isd_binary_with_fixed_p2(n, k, t, p2);
            if min < res {
                res = min;
            }
        }
        res
    }

    /// The security of the lpn parameters under SD attack for binary field. See The equation with s = 0 in page 39 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    ///
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_under_sd_binary(n: usize, k: usize, t: usize) -> f64 {
        let cost = Float::with_val(PRECISION, n - t + 1) / Float::with_val(PRECISION, n - k - t);

        let cost = cost.log2() * 2 * t + 2;

        let cost: Float = Float::with_val(PRECISION, k + 1).log2() + cost;
        cost.to_f64()
    }

    /// The security of the lpn parameters under SD 2.0 attack for binary field. See The equation with in page 39 in this [paper](https://eprint.iacr.org/2022/712.pdf).
    ///
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_under_sd2_binary(n: usize, k: usize, t: usize) -> f64 {
        let s = Self::security_under_pooled_gauss(n, k, t) as usize;
        Self::security_under_sd_binary(n, k - s, t)
    }

    /// The security of the exact lpn parameters for binary field.
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_for_binary(n: usize, k: usize, t: usize) -> f64 {
        let funcs: Vec<fn(usize, usize, usize) -> f64> = vec![
            Self::security_under_pooled_gauss,
            Self::security_under_sd_binary,
            Self::security_under_sd2_binary,
            Self::security_under_sd_isd_binary,
            Self::security_under_bjmm_isd_binary,
        ];

        let res: Vec<f64> = funcs.par_iter().map(|&func| func(n, k, t)).collect();

        res.into_iter()
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .expect("Some error in finding min")
    }

    fn cost_agb_binary(n: usize, k: usize, t: usize, f: usize, mu: usize) -> f64 {
        let f = Float::with_val(PRECISION, f);
        let mu = Float::with_val(PRECISION, mu);
        let beta = Float::with_val(PRECISION, n / t);

        let beta_minus_mu_minus_one: Float = beta.clone() - mu - 1;

        let a1 = beta_minus_mu_minus_one.clone() * f.clone();
        let a2: Float = beta_minus_mu_minus_one.clone().pow(2) * f.clone() * (f.clone() - 1) / 2;
        let a3: Float =
            beta_minus_mu_minus_one.clone().pow(3) * f.clone() * (f.clone() - 1) * (f.clone() - 2)
                / 6;
        let a4 = beta_minus_mu_minus_one.pow(4)
            * f.clone()
            * (f.clone() - 1)
            * (f.clone() - 2)
            * (f.clone() - 3)
            / 24;

        let beta_minus_one: Float = beta - 1;
        let t_minus_f = Float::with_val(PRECISION, t - f);

        let b1 = beta_minus_one.clone() * t_minus_f.clone();
        let b2: Float =
            beta_minus_one.clone().pow(2) * t_minus_f.clone() * (t_minus_f.clone() - 1) / 2;
        let b3: Float = beta_minus_one.clone().pow(3)
            * t_minus_f.clone()
            * (t_minus_f.clone() - 1)
            * (t_minus_f.clone() - 2)
            / 6;
        let b4 = beta_minus_one.pow(4)
            * t_minus_f.clone()
            * (t_minus_f.clone() - 1)
            * (t_minus_f.clone() - 2)
            * (t_minus_f - 3)
            / 24;

        let c1 = -Self::cal_comb(n - k - 1, 1);
        let c2 = Self::cal_comb(n - k, 2);
        let c3 = -Self::cal_comb(n - k + 1, 3);
        let c4 = Self::cal_comb(n - k + 2, 4);

        let d2 = a1.clone()
            + b1.clone()
            + c1.clone()
            + a1.clone() * b1.clone()
            + a1.clone() * c1.clone()
            + b1.clone() * c1.clone()
            + a2.clone()
            + b2.clone()
            + c2.clone();

        let d3 = c3.clone()
            + b1.clone() * c2.clone()
            + b2.clone() * c1.clone()
            + b3.clone()
            + a1.clone() * (b1.clone() * c1.clone() + b2.clone() + c2.clone())
            + a2.clone() * (b1.clone() + c1.clone())
            + a3.clone();

        let d4 = c4
            + b1.clone() * c3.clone()
            + b2.clone() * c2.clone()
            + b3.clone() * c1.clone()
            + b4
            + a1 * (b1.clone() * c2.clone() + b2.clone() * c1.clone() + b3 + c3)
            + a2 * (b2 + c2 + b1.clone() * c1.clone())
            + a3 * (b1 + c1)
            + a4;

        if d2 < 1 {
            return 2.0;
        }
        if d3 < 1 {
            return 3.0;
        }
        if d4 < 1 {
            return 4.0;
        }
        0.0
    }

    fn sub_agb_binary(n: usize, k: usize, t: usize, f: usize, mu: usize) -> f64 {
        let mu_copy = mu;
        let beta_copy = n / t;
        let f_copy = f;
        let f = Float::with_val(PRECISION, f);
        let mu = Float::with_val(PRECISION, mu);
        let beta = Float::with_val(PRECISION, n / t);

        let beta_minus_mu_minus_one: Float = beta.clone() - mu - 1;

        let a1 = beta_minus_mu_minus_one.clone() * f.clone();
        let a2: Float = beta_minus_mu_minus_one.clone().pow(2) * f.clone() * (f.clone() - 1) / 2;
        let a3: Float =
            beta_minus_mu_minus_one.clone().pow(3) * f.clone() * (f.clone() - 1) * (f.clone() - 2)
                / 6;
        let a4 = beta_minus_mu_minus_one.pow(4)
            * f.clone()
            * (f.clone() - 1)
            * (f.clone() - 2)
            * (f.clone() - 3)
            / 24;

        let beta_minus_one: Float = beta - 1;
        let t_minus_f: Float = Float::with_val(PRECISION, t - f);

        let b1 = beta_minus_one.clone() * t_minus_f.clone();
        let b2: Float =
            beta_minus_one.clone().pow(2) * t_minus_f.clone() * (t_minus_f.clone() - 1) / 2;
        let b3: Float = beta_minus_one.clone().pow(3)
            * t_minus_f.clone()
            * (t_minus_f.clone() - 1)
            * (t_minus_f.clone() - 2)
            / 6;
        let b4 = beta_minus_one.pow(4)
            * t_minus_f.clone()
            * (t_minus_f.clone() - 1)
            * (t_minus_f.clone() - 2)
            * (t_minus_f - 3)
            / 24;

        let d = Self::cost_agb_binary(n, k, t, f_copy, mu_copy);
        let mut cost = a1.clone() + b1.clone() + a1.clone() * b1.clone() + a2.clone() + b2.clone();
        if d == 2.0 {
            cost += 0;
        } else if d == 3.0 {
            let d3 = b3 + a1 * b2 + a2 * b1 + a3;
            cost += d3;
        } else if d == 4.0 {
            let d3 = b3.clone() + a1.clone() * b2.clone() + a2.clone() * b1.clone() + a3.clone();
            let d4 = b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4;
            cost += d3 + d4;
        } else {
            return u32::MAX as f64;
        }

        let res: Float = 2 * cost.log2()
            + Float::with_val(PRECISION, 3 * (k + 1 - f_copy * mu_copy)).log2()
            - f_copy
                * Float::with_val(PRECISION, 1.0 - (mu_copy as f64) / (beta_copy as f64)).log2();

        res.to_f64()
    }

    fn security_under_agb_binary(n: usize, k: usize, t: usize) -> f64 {
        let mut res = u32::MAX as f64;
        for f in 0..t {
            for mu in 0..n / t {
                if f * mu < k + 1 {
                    let cost = Self::sub_agb_binary(n, k, t, f, mu);
                    if res > cost {
                        res = cost;
                    }
                }
            }
        }
        res
    }

    /// The security of the regular lpn parameters for binary field.
    /// # Arguments.
    ///
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The Hamming weight of the error.
    ///
    /// NOTE: Run it in the release mode.
    pub fn security_for_binary_regular(n: usize, k: usize, t: usize) -> f64 {
        let cost_agb = Self::security_under_agb_binary(n, k, t);

        let n = n - t;
        let k = k - t;
        let cost_others = Self::security_for_binary(n, k, t);
        cost_agb.min(cost_others)
    }
}

mod tests {
    #[test]
    fn security_test() {
        let security = crate::LpnEstimator::security_for_binary_regular(1 << 10, 100, 10);
        println!("{:?}", security);
    }
}
