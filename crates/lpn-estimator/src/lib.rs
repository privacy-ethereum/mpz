mod lpn;

pub use lpn::LpnEstimator;

#[derive(Copy, Clone, Debug)]
pub enum LpnType {
    Exact,
    Regular,
}

#[derive(Copy, Clone, Debug)]
pub struct LpnParams {
    typ: LpnType,
    n: u64,
    k: u64,
    t: u64,
    s: f64,
}

impl LpnParams {
    pub fn new(typ: LpnType, n: u64, k: u64, t: u64) -> Self {
        let s = match typ {
            LpnType::Exact => LpnEstimator::security_for_binary(n, k, t),
            LpnType::Regular => LpnEstimator::security_for_binary_regular(n, k, t),
        };

        Self { typ, n, k, t, s }
    }

    pub fn scan(typ: LpnType, s: f64, k: u64, max_n: Option<u64>) -> Vec<LpnParams> {
        const MIN_K: u64 = 1024;
        assert!(k >= MIN_K, "k must be greter than {MIN_K}");

        const MAX_STEP: u32 = 4;
        const MIN_T: u64 = 256;

        // Do not scan for n >~ 100_000_000
        const MAX_N: u64 = 1 << 27;
        let max_n = max_n.unwrap_or(MAX_N);

        let mut lpns = vec![];
        let mut n = 2 * k;
        let mut t = MIN_T;

        let mut step_n = 0;
        let mut step_t = 0;

        loop {
            let cur_n = n + n / 2_u64.pow(step_n);
            let cur_t = t + t / 2_u64.pow(step_t);

            let lpn = Self::new(typ, cur_n, k, cur_t);

            if lpn.s > s {
                lpns.push(lpn);
                n = cur_n;
                step_n = 0;
                step_t = 0;
            } else if step_n < MAX_STEP {
                step_n += 1;
            } else if step_t < MAX_STEP {
                t = cur_t;
                step_t += 1;
            } else {
                step_n = 0;
                step_t = 0;
                t *= 2;
            }

            if t > k / 2 || n > max_n {
                break;
            }
        }

        lpns
    }

    pub fn typ(&self) -> LpnType {
        self.typ
    }

    pub fn security(&self) -> f64 {
        self.s
    }

    pub fn nkt(&self) -> (u64, u64, u64) {
        (self.n, self.k, self.t)
    }
}
