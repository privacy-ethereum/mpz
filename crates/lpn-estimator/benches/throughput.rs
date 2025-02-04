use lpn_estimator::{LpnEstimator, LpnParams, LpnType};

fn main() {
    divan::main();
}

const N: &[(u64, u64, u64)] = &[
    (10_000, 500, 100),
    (100_000, 5_000, 200),
    (1_000_000, 50_000, 500),
    (10_000_000, 500_000, 1_000),
];

#[divan::bench(args = N, max_time = 10)]
fn exact((n, k, t): (u64, u64, u64)) -> f64 {
    LpnEstimator::security_for_binary(n, k, t)
}

#[divan::bench(args = N, max_time = 10)]
fn regular((n, k, t): (u64, u64, u64)) -> f64 {
    LpnEstimator::security_for_binary_regular(n, k, t)
}

#[divan::bench(max_time = 10)]
fn scan_exact() {
    LpnParams::scan(LpnType::Exact, 128., N[1].1, None);
}

#[divan::bench(max_time = 10)]
fn scan_regular() {
    LpnParams::scan(LpnType::Regular, 128., N[1].1, None);
}
