//! Temporary per-phase profiling harness for the Ferret extension.
//!
//! Run with:
//!   cargo test -p mpz-ot-core --release --features rayon \
//!       ferret::profile -- --nocapture --ignored
//!
//! Drives the *real* phase functions (cuckoo bucket construction, SPCOT GGM
//! generation, MPCOT combine, consistency check, LPN encode) at production LPN
//! parameters and reports the wall-clock spent in each, so we can attribute
//! cost without protocol/network/serialization overhead.

use std::time::Instant;

use rand::{RngExt, SeedableRng, rngs::StdRng};

use mpz_core::{
    Block,
    bitvec::BitVec,
    lpn::{LpnEncoder, LpnParameters, LpnType, sample_error_indices},
};

use crate::ferret::{
    config::{CSP, REGULAR_PARAMS, UNIFORM_PARAMS},
    mpcot::{MPCOTReceiver, MPCOTSender},
    spcot::SPCOTSender,
};

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

#[test]
#[ignore = "profiling harness, run explicitly with --ignored --nocapture"]
fn profile_ferret_phases() {
    let param_indices = [0usize, 2, 4];

    for (lpn_type, params) in [
        (LpnType::Uniform, UNIFORM_PARAMS),
        (LpnType::Regular, REGULAR_PARAMS),
    ] {
        println!("\n=== LpnType::{lpn_type:?} ===");
        println!(
            "{:>9} {:>9} {:>11} | {:>10} {:>10} {:>8} {:>8} {:>8} {:>8} | {:>10}",
            "n",
            "k",
            "ggm_leaves",
            "cuckoo_snd",
            "cuckoo_rcv",
            "spcot",
            "combine",
            "check",
            "lpn_enc",
            "SIDE_TOTAL",
        );

        for &pi in &param_indices {
            profile_one(lpn_type, params[pi]);
        }
    }
    println!("\n(all times in ms; rayon = {})", cfg!(feature = "rayon"));
}

fn profile_one(lpn_type: LpnType, params: LpnParameters) {
    let LpnParameters { n, k, t } = params;
    {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: Block = rng.random();
        let cuckoo_seed: Block = rng.random();

        // ---- sender cuckoo bucket construction ----
        let t0 = Instant::now();
        let (mpcot_send, log2_lengths) = MPCOTSender::new(cuckoo_seed, lpn_type)
            .start_extend(t, n)
            .unwrap();
        let t_cuckoo_send = t0.elapsed();

        // ---- receiver cuckoo (CuckooHash insert + Buckets) ----
        let idxs = sample_error_indices(&mut rng, lpn_type, n, t);
        let t0 = Instant::now();
        let _ = MPCOTReceiver::new(cuckoo_seed, lpn_type)
            .start_extend(&idxs, n)
            .unwrap();
        let t_cuckoo_recv = t0.elapsed();

        // SPCOT inputs sized exactly as the protocol would.
        let sum_log2: usize = log2_lengths.iter().sum();
        let keys: Vec<Block> = (0..sum_log2).map(|_| rng.random()).collect();
        let masks: BitVec = (0..sum_log2).map(|_| rng.random::<bool>()).collect();
        let ggm_leaves: usize = log2_lengths.iter().map(|l| 1usize << l).sum();

        // ---- SPCOT sender extend (GGM gen + fixed-key AES) ----
        let mut spcot = SPCOTSender::new(delta);
        let t0 = Instant::now();
        let (vs, _ms_out, _sums) = spcot
            .extend(&mut rng, &log2_lengths, &keys, &masks)
            .unwrap();
        let t_spcot = t0.elapsed();

        // ---- MPCOT combine (random-access XOR gather) ----
        let t0 = Instant::now();
        let res = mpcot_send.extend(vs).unwrap();
        let t_combine = t0.elapsed();
        debug_assert_eq!(res.len(), n);

        // ---- consistency check (chi gen + O(leaves) inner product) ----
        let check_keys: Vec<Block> = (0..CSP).map(|_| rng.random()).collect();
        let check_masks: BitVec = (0..CSP).map(|_| rng.random::<bool>()).collect();
        let t0 = Instant::now();
        let _hashed = spcot.check(&check_keys, &check_masks).unwrap();
        let t_check = t0.elapsed();

        // ---- LPN encode  y = A*v + s ----
        let x: Vec<Block> = (0..k).map(|_| rng.random()).collect();
        let mut y = res;
        let enc = LpnEncoder::<10>::new(k as u32);
        let lpn_seed: Block = rng.random();
        let t0 = Instant::now();
        enc.compute(lpn_seed, &mut y, &x);
        let t_lpn = t0.elapsed();
        std::hint::black_box(&y);

        // One party (sender) pays: cuckoo + spcot + combine + check + lpn.
        let side_total = t_cuckoo_send + t_spcot + t_combine + t_check + t_lpn;

        println!(
            "{:>9} {:>9} {:>11} | {:>10.1} {:>10.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} | {:>10.1}",
            n,
            k,
            ggm_leaves,
            ms(t_cuckoo_send),
            ms(t_cuckoo_recv),
            ms(t_spcot),
            ms(t_combine),
            ms(t_check),
            ms(t_lpn),
            ms(side_total),
        );
    }
}
