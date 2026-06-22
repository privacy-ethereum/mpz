//! End-to-end tests for the `GF(2^64)` circuit path: build a small arithmetic
//! circuit over `Gf2_64`, drive it through the [`Commit`]/[`Prover`]/[`Verifier`]
//! triple against a simulated subfield sVOLE tape, and check that the
//! QuickSilver consistency check accepts a correct execution and rejects a
//! corrupted one.

use mpz_circuits::Context;
use mpz_fields::{ExtensionField, gf2_64::Gf2_64, gf2_128::Gf2_128};
use mpz_zk_core::{
    DeltaPowers, PolyContext, ProverOutput, VerifierOutput,
    gf64::{Auth64, Commit, Prover, Verifier},
    vope_receiver, vope_sender,
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha12Rng;

const VOPE_COST: usize = 128;

/// Subfield injection `GF(2^64) ↪ GF(2^128)`.
fn embed(v: Gf2_64) -> Gf2_128 {
    <Gf2_128 as ExtensionField<Gf2_64>>::embed(v)
}

/// The benchmark circuit: `out = ((i0·i1) + i2)·i1 + 5`, asserted to equal the
/// public `expected`. Two multiplications consume the gate tape.
fn circuit<C>(ctx: &mut C, inputs: &[C::Wire], expected: Gf2_64) -> Result<(), C::Error>
where
    C: Context<Field = Gf2_64>,
{
    let a = ctx.mul(inputs[0], inputs[1]);
    let b = ctx.add(a, inputs[2]);
    let c = ctx.mul(b, inputs[1]);
    let five = ctx.constant(Gf2_64(5));
    let out = ctx.add(c, five);
    ctx.assert_const(out, expected)
}

/// Cleartext evaluation of [`circuit`] for the expected output.
fn eval(i: &[Gf2_64; 3]) -> Gf2_64 {
    let a = i[0] * i[1];
    let b = a + i[2];
    let c = b * i[1];
    c + Gf2_64(5)
}

const N_IN: usize = 3;
const N_GATE: usize = 2;

struct Setup {
    delta: Gf2_128,
    /// Prover input wires (value + raw MAC).
    input_auth: Vec<Auth64>,
    /// Verifier input wires (adjusted keys).
    input_keys: Vec<Gf2_128>,
    /// Cleartext input values (for the commit pass).
    input_values: [Gf2_64; N_IN],
    gate_masks: Vec<Gf2_64>,
    gate_macs: Vec<Gf2_128>,
    gate_keys: Vec<Gf2_128>,
    expected: Gf2_64,
    vope_choices: [bool; VOPE_COST],
    vope_ev: [Gf2_128; VOPE_COST],
    vope_keys: [Gf2_128; VOPE_COST],
    chi: [u8; 32],
}

/// Samples a subfield sVOLE tape and commits the inputs, returning everything
/// the prover and verifier need.
fn setup(seed: u64) -> Setup {
    let mut rng = StdRng::seed_from_u64(seed);
    let delta = Gf2_128::new(rng.random());

    let input_values: [Gf2_64; N_IN] = core::array::from_fn(|_| Gf2_64(rng.random()));
    let expected = eval(&input_values);

    // Subfield sVOLE: per entry, choice ∈ GF(2^64), key ∈ GF(2^128),
    // mac = key + embed(choice)·Δ.
    let total = N_IN + N_GATE;
    let choices: Vec<Gf2_64> = (0..total).map(|_| Gf2_64(rng.random())).collect();
    let keys: Vec<Gf2_128> = (0..total).map(|_| Gf2_128::new(rng.random())).collect();
    let macs: Vec<Gf2_128> = (0..total)
        .map(|i| keys[i] + embed(choices[i]) * delta)
        .collect();

    // Commit the inputs: adjust = value + choice, key adjusted, mac raw.
    let input_auth: Vec<Auth64> = (0..N_IN)
        .map(|i| Auth64 {
            value: input_values[i],
            mac: macs[i],
        })
        .collect();
    let input_keys: Vec<Gf2_128> = (0..N_IN)
        .map(|i| {
            let adjust = input_values[i] + choices[i];
            keys[i] + embed(adjust) * delta
        })
        .collect();

    // Gate tape: masks start at the sVOLE choices; the commit pass overwrites
    // them with adjustments.
    let gate_masks: Vec<Gf2_64> = choices[N_IN..].to_vec();
    let gate_macs: Vec<Gf2_128> = macs[N_IN..].to_vec();
    let gate_keys: Vec<Gf2_128> = keys[N_IN..].to_vec();

    // VOPE correlation (single GF(2^128) line over 128 bit-choices).
    let vope: Vec<(bool, Gf2_128, Gf2_128)> = (0..VOPE_COST)
        .map(|_| {
            let choice: bool = rng.random();
            let key = Gf2_128::new(rng.random());
            let mac = if choice { key + delta } else { key };
            (choice, mac, key)
        })
        .collect();
    let vope_choices: [bool; VOPE_COST] = core::array::from_fn(|i| vope[i].0);
    let vope_ev: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| vope[i].1);
    let vope_keys: [Gf2_128; VOPE_COST] = core::array::from_fn(|i| vope[i].2);
    let chi: [u8; 32] = rng.random();

    Setup {
        delta,
        input_auth,
        input_keys,
        input_values,
        gate_masks,
        gate_macs,
        gate_keys,
        expected,
        vope_choices,
        vope_ev,
        vope_keys,
        chi,
    }
}

/// Runs the prover's two passes and returns the masked `(u, v, assertions)`
/// and the gate adjust tape for the verifier.
fn prove(s: &Setup) -> (Gf2_128, Gf2_128, [u8; 32], Vec<Gf2_64>) {
    let mut gate_adjust = s.gate_masks.clone();
    let mut commit = Commit::new(&mut gate_adjust);
    circuit(&mut commit, &s.input_values, s.expected).unwrap();
    commit.finish().unwrap();

    let mut prover = Prover::committed(&s.gate_macs).accumulate(ChaCha12Rng::from_seed(s.chi));
    circuit(&mut prover, &s.input_auth, s.expected).unwrap();
    let ProverOutput { u, v, assertions, .. } = prover.finish().unwrap();

    let (a_0, a_1) = vope_receiver(&s.vope_choices, &s.vope_ev);
    (u + a_0, v + a_1, assertions, gate_adjust)
}

/// Runs the verifier's accumulate pass and returns `(w + b, assertions)`.
fn verify(s: &Setup, gate_adjust: &[Gf2_64]) -> (Gf2_128, [u8; 32]) {
    let verifier = Verifier::new(s.delta, &s.gate_keys, gate_adjust).unwrap();
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(s.chi));
    circuit(&mut verifier, &s.input_keys, s.expected).unwrap();
    let VerifierOutput { w, assertions, .. } = verifier.finish().unwrap();
    (w + vope_sender(&s.vope_keys), assertions)
}

#[test]
fn happy_path() {
    let s = setup(1);
    let (u, v, p_assertions, gate_adjust) = prove(&s);
    let (wb, v_assertions) = verify(&s, &gate_adjust);

    assert_eq!(p_assertions, v_assertions, "assertion hashes must match");
    assert_eq!(wb, u + s.delta * v, "consistency check must accept");
}

#[test]
fn corrupted_gate_rejected() {
    // Honest prover, then corrupt a verifier gate key before its pass: the
    // triple's z no longer matches, so the check equation fails.
    let mut s = setup(2);
    let (u, v, _p_assertions, gate_adjust) = prove(&s);

    s.gate_keys[0] = s.gate_keys[0] + Gf2_128::new(0xdead_beef);

    let (wb, _v_assertions) = verify(&s, &gate_adjust);
    assert_ne!(wb, u + s.delta * v, "corrupted gate must be rejected");
}

#[test]
fn wrong_expected_breaks_assertion() {
    // The assertion binds the claimed public output: a verifier checking a
    // different output reconstructs a different MAC, so the hashes diverge.
    let s = setup(3);
    let (_u, _v, p_assertions, gate_adjust) = prove(&s);

    let verifier = Verifier::new(s.delta, &s.gate_keys, &gate_adjust).unwrap();
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(s.chi));
    let wrong = s.expected + Gf2_64(1);
    circuit(&mut verifier, &s.input_keys, wrong).unwrap();
    let VerifierOutput { assertions: v_assertions, .. } = verifier.finish().unwrap();

    assert_ne!(
        p_assertions, v_assertions,
        "a wrong claimed output must break the assertion hash"
    );
}

#[test]
fn unsatisfying_witness_fails_commit() {
    // The commit pass evaluates in cleartext and catches a witness that does
    // not satisfy the asserted output early.
    let s = setup(5);
    let mut masks = s.gate_masks.clone();
    let mut commit = Commit::new(&mut masks);
    let wrong = s.expected + Gf2_64(1);
    assert!(circuit(&mut commit, &s.input_values, wrong).is_err());
}

#[test]
fn tape_length_mismatch_rejected() {
    let s = setup(4);
    let bad_adjust = vec![Gf2_64(0); s.gate_keys.len() + 1];
    assert!(Verifier::new(s.delta, &s.gate_keys, &bad_adjust).is_err());
}

// --- polynomial-constraint path --------------------------------------------

/// A degree-2 polynomial constraint `x·y − z = 0` over committed `GF(2^64)`
/// wires, plus a degree-3 `x·y·u − w = 0`, exercising the `PolyContext`.
fn poly_gadget<C>(ctx: &mut C, w: &[C::Wire]) -> Result<(), C::Error>
where
    C: PolyContext<Field = Gf2_64>,
    C::Error: core::fmt::Debug,
{
    let x = ctx.lift(w[0]);
    let y = ctx.lift(w[1]);
    let z = ctx.lift(w[2]);
    let u = ctx.lift(w[3]);
    let ww = ctx.lift(w[4]);
    ctx.assert_zero(x * y - z)?; // degree 2
    ctx.assert_zero(x * y * u - ww)?; // degree 3
    Ok(())
}

const POLY_DMAX: usize = 3;

#[test]
fn poly_round_trip() {
    let mut rng = StdRng::seed_from_u64(20);
    let delta = Gf2_128::new(rng.random());
    let powers = DeltaPowers::new(delta);
    let chi: [u8; 32] = rng.random();

    // Witness: x, y, z = x·y, u, w = x·y·u — five committed values.
    let x = Gf2_64(rng.random());
    let y = Gf2_64(rng.random());
    let u = Gf2_64(rng.random());
    let z = x * y;
    let w = z * u;
    let values = [x, y, z, u, w];
    let n = values.len();

    // Subfield sVOLE for the five input wires.
    let choices: Vec<Gf2_64> = (0..n).map(|_| Gf2_64(rng.random())).collect();
    let keys: Vec<Gf2_128> = (0..n).map(|_| Gf2_128::new(rng.random())).collect();
    let macs: Vec<Gf2_128> = (0..n).map(|i| keys[i] + embed(choices[i]) * delta).collect();
    let input_auth: Vec<Auth64> = (0..n)
        .map(|i| Auth64 {
            value: values[i],
            mac: macs[i],
        })
        .collect();
    let input_keys: Vec<Gf2_128> = (0..n)
        .map(|i| keys[i] + embed(values[i] + choices[i]) * delta)
        .collect();

    // Mock degree-`d_max` polynomial-check VOPE.
    let poly_masks: Vec<Gf2_128> = (0..POLY_DMAX).map(|_| Gf2_128::new(rng.random())).collect();
    let mut vope_sum = Gf2_128::new(0);
    let mut pw = Gf2_128::new(1);
    for &m in &poly_masks {
        vope_sum = vope_sum + m * pw;
        pw = pw * delta;
    }

    // Commit pass validates the witness in cleartext.
    let mut commit = Commit::new(&mut []);
    poly_gadget(&mut commit, &values).unwrap();
    commit.finish().unwrap();

    // Prover accumulate.
    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(chi));
    poly_gadget(&mut prover, &input_auth).unwrap();
    let ProverOutput { poly, .. } = prover.finish().unwrap();
    let coefficients: Vec<Gf2_128> = poly
        .coefficients(POLY_DMAX)
        .unwrap()
        .into_iter()
        .zip(&poly_masks)
        .map(|(c, &m)| c + m)
        .collect();

    // Verifier accumulate + check.
    let verifier = Verifier::new(delta, &[], &[]).unwrap();
    let mut verifier = verifier.accumulate(ChaCha12Rng::from_seed(chi));
    poly_gadget(&mut verifier, &input_keys).unwrap();
    let VerifierOutput { poly: vpoly, .. } = verifier.finish().unwrap();

    vpoly.check(&powers, &coefficients, vope_sum).unwrap();

    // A corrupted coefficient must fail the check.
    let mut bad = coefficients.clone();
    bad[0] = bad[0] + Gf2_128::ONE;
    assert!(vpoly.check(&powers, &bad, vope_sum).is_err());
}

#[test]
fn poly_unsatisfied_rejected() {
    // An unsatisfying witness (z ≠ x·y) is caught by the prover's local
    // assert_zero during the accumulate pass.
    let mut rng = StdRng::seed_from_u64(21);
    let delta = Gf2_128::new(rng.random());
    let chi: [u8; 32] = rng.random();

    let x = Gf2_64(rng.random());
    let y = Gf2_64(rng.random());
    let u = Gf2_64(rng.random());
    let values = [x, y, x * y + Gf2_64(1), u, x * y * u]; // z is wrong

    let n = values.len();
    let choices: Vec<Gf2_64> = (0..n).map(|_| Gf2_64(rng.random())).collect();
    let keys: Vec<Gf2_128> = (0..n).map(|_| Gf2_128::new(rng.random())).collect();
    let macs: Vec<Gf2_128> = (0..n).map(|i| keys[i] + embed(choices[i]) * delta).collect();
    let input_auth: Vec<Auth64> = (0..n)
        .map(|i| Auth64 {
            value: values[i],
            mac: macs[i],
        })
        .collect();

    let mut prover = Prover::committed(&[]).accumulate(ChaCha12Rng::from_seed(chi));
    assert!(poly_gadget(&mut prover, &input_auth).is_err());
}
