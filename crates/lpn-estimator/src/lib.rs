mod lpn;

pub use lpn::LpnEstimator;

use proc_macro2::TokenStream;
use quote::{ToTokens, quote};

/// The primal LPN type.
#[derive(Copy, Clone, Debug)]
pub enum LpnType {
    Exact,
    Regular,
}

/// Parameters for an LPN instance.
#[derive(Copy, Clone, Debug)]
pub struct LpnParams {
    typ: LpnType,
    n: u64,
    k: u64,
    t: u64,
    s: f64,
}

impl ToTokens for LpnParams {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let n = self.n as usize;
        let k = self.k as usize;
        let t = self.t as usize;

        let out = quote! {
            LpnParameters {
                n: #n,
                k: #k,
                t: #t
            }
        };
        tokens.extend(out);
    }
}

impl LpnParams {
    /// Creates a primal LPN instance and computes the bit security.
    ///
    /// # Arguments
    ///
    /// * `typ` - The LPN type.
    /// * `n` - The number of samples.
    /// * `k` - The length of the secret.
    /// * `t` - The hamming weight of the noise.
    pub fn new(typ: LpnType, n: u64, k: u64, t: u64) -> Self {
        let s = match typ {
            LpnType::Exact => LpnEstimator::security_for_binary(n, k, t),
            LpnType::Regular => LpnEstimator::security_for_binary_regular(n, k, t),
        };

        Self { typ, n, k, t, s }
    }

    /// Scans the parameter space for LPN instances based on some fixed `t` and a minimum bit
    /// security.
    ///
    /// Tries to maximize `n` while keeping `k` small and staying above a minimum provided bit
    /// security.
    ///
    /// # Arguments
    ///
    /// * `typ` - The LPN type.
    /// * `t` - The hamming weight of the error vector.
    /// * `s` - The minimum bit security.
    /// * `max_n` - The maximum number of samples to consider.
    pub fn scan(typ: LpnType, s: f64, t: u64, max_n: Option<u64>) -> Vec<LpnParams> {
        const MIN_T: u64 = 1000;
        assert!(t >= MIN_T, "t must be greter than {MIN_T}");

        const MAX_STEP: u32 = 4;

        const MAX_N: u64 = 10_000_000;
        let max_n = max_n.unwrap_or(MAX_N);

        let mut lpns = vec![];
        let mut n = 200 * t;
        let mut k = 20 * t;

        let mut step_n = 0;
        let mut step_k = 0;

        loop {
            let cur_n = n + n / 2_u64.pow(step_n);
            let cur_k = k + k / 2_u64.pow(MAX_STEP - step_k + 1);

            let lpn = Self::new(typ, cur_n, cur_k, t);

            if lpn.s > s {
                lpns.push(lpn);
                n = cur_n;
                step_n = 0;
                step_k = 0;
            } else if step_n < MAX_STEP {
                step_n += 1;
            } else if step_k < MAX_STEP {
                step_k += 1;
            } else {
                step_n = 0;
                step_k = 0;
                k *= 2;
            }

            if n > max_n {
                break;
            }
        }

        lpns
    }

    /// Returns the LPN type.
    pub fn typ(&self) -> LpnType {
        self.typ
    }

    /// Returns the bit security.
    pub fn security(&self) -> f64 {
        self.s
    }

    /// Returns n, the number of samples.
    pub fn n(&self) -> u64 {
        self.n
    }

    /// Returns k, the length of the secret.
    pub fn k(&self) -> u64 {
        self.k
    }

    /// Returns t, the hamming weight of the noise.
    pub fn t(&self) -> u64 {
        self.t
    }
}
