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
    /// * `s` - The minimum bit security.
    /// * `t` - The hamming weight of the error vector.
    /// * `max_n` - The maximum number of samples to consider.
    pub fn scan(typ: LpnType, s: f64, t: u64, max_n: Option<u64>) -> Vec<LpnParams> {
        const MIN_T: u64 = 1000;
        assert!(t >= MIN_T, "t must be greter than {MIN_T}");

        const MAX_N: u64 = 100_000_000;
        let max_n = max_n.unwrap_or(MAX_N);

        const START_EXP: u64 = 9;
        let mut exp = START_EXP;

        let calc_n = |t: u64, exp: u64| (1 << exp) * t;
        let mut k: u64 = START_EXP * t;

        let mut lpns = vec![];
        loop {
            let n = calc_n(t, exp);
            let lpn = Self::new(typ, n, k, t);

            if lpn.security() >= s {
                exp += 3;
                lpns.push(lpn);
            } else {
                k += k / 20;
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
