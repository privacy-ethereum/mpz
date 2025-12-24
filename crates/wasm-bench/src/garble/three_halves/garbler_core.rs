//! Benchmarks for mpz-garble-core garbler primitives.
//!
//! Measures raw three-halves garbling performance without protocol overhead.

use wasm_bindgen::prelude::*;

use mpz_circuits::AES128;
use mpz_garble_core::three_halves::Garbler;
use mpz_memory_core::correlated::{Delta, Key};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// Shared benchmark state, initialized once.
struct BenchState {
    delta: Delta,
    inputs: Vec<Key>,
}

impl BenchState {
    fn new() -> Self {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let inputs: Vec<Key> = (0..256).map(|_| rng.random()).collect();

        Self { delta, inputs }
    }
}

thread_local! {
    static STATE: BenchState = BenchState::new();
}

/// Benchmark three-halves garbling: garble AES circuit n times.
/// Returns a checksum to prevent optimization.
#[wasm_bindgen]
pub fn garble_core_three_halves_garble(n: u32) -> u32 {
    STATE.with(|state| {
        let mut gb = Garbler::default();
        let mut rng = StdRng::seed_from_u64(0);
        let mut checksum = 0u32;

        for _ in 0..n {
            let mut iter = gb.generate(&AES128, state.delta, &state.inputs, &mut rng).unwrap();
            let gates: Vec<_> = iter.by_ref().collect();
            let _ = iter.finish().unwrap();
            checksum = checksum.wrapping_add(gates.len() as u32);
        }

        checksum
    })
}
