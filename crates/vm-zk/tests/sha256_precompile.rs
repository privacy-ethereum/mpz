//! Integration tests for the `crypto::sha256_compress` host call: the VM
//! runs the SHA-256 compression circuit directly instead of replaying guest
//! gates. Covers the authenticated path (committed inputs, output committed and
//! revealed for the check), the public fast-path (all inputs public, no gates),
//! and segmented boundary stitching of the in-place output across two chained
//! compressions.

use futures::{executor::block_on, future::try_join};
use mpz_common::context::test_st_context;
use mpz_core::Block;
use mpz_ot::ideal::rcot::ideal_rcot;
use mpz_vm_core::{Param, Vm, Write, value::Value};
use mpz_vm_ir::{ExportKind, Module};
use mpz_vm_zk::{Config, Prover, Verifier};
use rand::{Rng, SeedableRng, rngs::StdRng};

/// A guest exposing the compression precompile: `compress_once` compresses one
/// block into the state in place; `compress_twice` chains two blocks into the
/// same state. The state is compressed in place with no copy — the precompile
/// reads the state (public IV, then the committed prior output) and the block
/// and writes the new state back over `$state` atomically.
const GUEST: &str = r#"(module
    (import "crypto" "sha256_compress" (func $compress (param i32 i32)))
    (memory (export "mem") 2)
    (func (export "compress_once") (param $state i32) (param $block i32)
        (call $compress (local.get $state) (local.get $block)))
    (func (export "compress_twice") (param $state i32) (param $b1 i32) (param $b2 i32)
        (call $compress (local.get $state) (local.get $b1))
        (call $compress (local.get $state) (local.get $b2))))"#;

const STATE_PTR: u32 = 256;
const BLOCK_PTRS: [u32; 2] = [512, 768];

fn func_idx(module: &Module, name: &str) -> u32 {
    module
        .exports()
        .iter()
        .find_map(|e| match e.kind {
            ExportKind::Func(idx) if e.name == name => Some(idx),
            _ => None,
        })
        .expect("function should be exported")
}

/// Reference SHA-256 compression of `blocks` into `state`. The state is the
/// precompile's `[u32; 8]`, little-endian in linear memory; the blocks are raw
/// bytes parsed as big-endian SHA-256 words.
fn reference(state: &[u8; 32], blocks: &[[u8; 64]]) -> [u8; 32] {
    let mut h: [u32; 8] =
        core::array::from_fn(|i| u32::from_le_bytes(state[4 * i..4 * i + 4].try_into().unwrap()));
    let blocks: Vec<_> = blocks.iter().map(|b| (*b).into()).collect();
    sha2::compress256(&mut h, &blocks);
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Proves `blocks.len()` chained compressions of `blocks` into `state0` through
/// the precompile and returns the resulting 32-byte state. With `public`, the
/// inputs are staged public (the fast-path); otherwise they are committed and
/// the output is revealed to read it back.
fn prove_compress(
    config: Config,
    state0: &[u8; 32],
    blocks: &[[u8; 64]],
    state_private: bool,
    block_private: bool,
) -> Vec<u8> {
    assert!((1..=2).contains(&blocks.len()));
    let module = Module::parse(&wat::parse_str(GUEST).unwrap()).unwrap();

    let mut rng = StdRng::seed_from_u64(0);
    let mut delta: Block = rng.random();
    delta.set_lsb(true);
    let (svole_sender, svole_receiver) = ideal_rcot(rng.random(), delta);
    let mut prover =
        Prover::new_with_config(module.clone(), svole_receiver, config.clone()).unwrap();
    let mut verifier = Verifier::new_with_config(module.clone(), svole_sender, config).unwrap();
    let (mut ctx_p, mut ctx_v) = test_st_context(8 << 20);

    // Stage the initial state and the blocks, each either public (both parties)
    // or private (prover) / blind (verifier). The state is compressed in place,
    // so staging it private exercises committing a region the host call then
    // overwrites.
    let mut staged: Vec<(u32, &[u8], bool)> = vec![(STATE_PTR, &state0[..], state_private)];
    for (b, &ptr) in blocks.iter().zip(&BLOCK_PTRS) {
        staged.push((ptr, &b[..], block_private));
    }
    for (ptr, data, private) in staged {
        if private {
            prover.write(ptr, Write::Private(data)).unwrap();
            verifier.write(ptr, Write::Blind(data.len())).unwrap();
        } else {
            prover.write(ptr, Write::Public(data)).unwrap();
            verifier.write(ptr, Write::Public(data)).unwrap();
        }
    }

    let n = blocks.len();
    let func = func_idx(&module, if n == 1 { "compress_once" } else { "compress_twice" });
    let params = || {
        let mut v = vec![Param::Public(Value::I32(STATE_PTR as i32))];
        for &ptr in BLOCK_PTRS.iter().take(n) {
            v.push(Param::Public(Value::I32(ptr as i32)));
        }
        v
    };

    block_on(try_join(
        prover.call(&mut ctx_p, func, params()),
        verifier.call(&mut ctx_v, func, params()),
    ))
    .unwrap();

    // The output is committed unless every input byte was public (the fast
    // path). Open it so the verifier can read it; this also checks the committed
    // output wires equal the proven circuit's.
    if state_private || block_private {
        prover.reveal(STATE_PTR, 32).unwrap();
        verifier.reveal(STATE_PTR, 32).unwrap();
        block_on(try_join(
            prover.commit(&mut ctx_p),
            verifier.commit(&mut ctx_v),
        ))
        .unwrap();
    }
    verifier.read(STATE_PTR, 32).unwrap().to_vec()
}

#[test]
fn precompile_authenticated_single_block() {
    let state0: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let block: [u8; 64] = core::array::from_fn(|i| i as u8);
    // Public IV state, private message block.
    let got = prove_compress(Config::builder().build(), &state0, &[block], false, true);
    assert_eq!(got.as_slice(), reference(&state0, &[block]));
}

#[test]
fn precompile_public_fast_path() {
    let state0: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(1));
    let block: [u8; 64] = core::array::from_fn(|i| (i as u8) ^ 0xa5);
    // All inputs public: the precompile computes in the clear, output public.
    let got = prove_compress(Config::builder().build(), &state0, &[block], false, false);
    assert_eq!(got.as_slice(), reference(&state0, &[block]));
}

#[test]
fn precompile_private_state_in_place() {
    let state0: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(2));
    let block: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(3));
    // The state is staged as a private host input at the very region the
    // compression overwrites in place: the commitment must capture the staged
    // value, not the digest written during capture.
    let got = prove_compress(Config::builder().build(), &state0, &[block], true, true);
    assert_eq!(got.as_slice(), reference(&state0, &[block]));
}

#[test]
fn precompile_segmented_two_blocks() {
    let state0: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11));
    let b1: [u8; 64] = core::array::from_fn(|i| i as u8);
    let b2: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_add(64));
    // A low segment cost forces a boundary between the two 22,696-gate
    // precompiles, stitching the first's in-place output state into the second.
    let config = Config::builder().segment_cost(Some(5_000)).build();
    let got = prove_compress(config, &state0, &[b1, b2], false, true);
    assert_eq!(got.as_slice(), reference(&state0, &[b1, b2]));
}
