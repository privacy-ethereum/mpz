// fpre.rs

// TODO: Move auth bits and auth triples into correlated.rs
// TODO: don't clone FpreGen and FpreEval, transfer ownership instead

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use mpz_memory_core::correlated::{Delta, Key, Mac};

/// A single share of a bit, belonging to one party.
/// The share is `(bit, key, mac)`.  The MAC is derived via:
///
/// ```ignore
/// mac = key.auth(bit, &delta)
/// ```
///
/// so that `mac.as_block() ^ key.as_block() == (bit ? delta.as_block() : 0)`.
#[derive(Debug, Clone, Default)]
pub struct AuthBitShare {
    /// Random key for this share.
    pub key: Key,
    /// MAC computed via `key.auth(bit, &delta)`.
    pub mac: Mac,
}

impl AuthBitShare {
    /// Retrieves the embedded bit from the LSB of `mac`.
    #[inline]
    pub fn bit(&self) -> bool {
        self.mac.pointer()
    }
}

/// Builds a share `(bit, key, mac)`, where `mac = key.auth(bit, delta)`.
fn build_share(rng: &mut ChaCha12Rng, bit: bool, delta: &Delta) -> AuthBitShare {
    // Generate a random Key
    let mut key: Key = rng.gen();
    key.set_pointer(false);
    // Use the built-in auth method
    let mac = key.auth(bit, delta);
    // mac.set_pointer(bit); not needed as Key has LSB 0, Delta has LSB 1. Compare with adjust.
    AuthBitShare {key, mac}
}

/// XORs two `AuthBitShare`s component-wise:
pub(crate) fn xor_auth_bit_share(left: &AuthBitShare, right: &AuthBitShare) -> AuthBitShare {
    AuthBitShare {
        key: left.key + right.key, 
        mac: left.mac + right.mac,
    }
}

/// A single “wire bit” is split between generator & evaluator:
///
/// `full_bit = gen_share.bit ^ eval_share.bit`  
///
/// The generator share is authenticated under `delta_b`, evaluator share under `delta_a`.
#[derive(Debug, Clone)]
pub struct AuthBit {
    pub gen_share: AuthBitShare,  // uses delta_b
    pub eval_share: AuthBitShare, // uses delta_a
}

impl AuthBit {
    /// Recover the full bit in our toy single-process code.
    pub fn full_bit(&self) -> bool {
        self.gen_share.bit() ^ self.eval_share.bit()
    }
}

/// A triple (x, y, z) also split between the two parties:
/// ```text
/// x = x_gen.bit ^ x_eval.bit
/// y = y_gen.bit ^ y_eval.bit
/// z = z_gen.bit ^ z_eval.bit
/// ```
/// and we want z = x & y (in this toy example).
#[derive(Debug, Clone)]
pub struct AuthTriple {
    pub x: AuthBit,
    pub y: AuthBit,
    pub z: AuthBit,
}

/// For convenience, group the three shares (x, y, z) that belong to **one** party
/// (i.e., x_gen, y_gen, z_gen) or (x_eval, y_eval, z_eval).
#[derive(Debug, Clone)]
pub struct AuthTripleShare {
    pub x: AuthBitShare,
    pub y: AuthBitShare,
    pub z: AuthBitShare,
}

/// The Fpre struct, showing how to integrate with your existing Key & Mac API.
#[derive(Debug)]
pub struct Fpre {
    rng: ChaCha12Rng,
    num_input_wires: usize,
    num_and_gates: usize,

    /// Global correlation for evaluator
    delta_a: Delta,
    /// Global correlation for generator
    delta_b: Delta,

    /// An array of wire bits (split into gen/eval shares).
    pub auth_bits: Vec<AuthBit>,
    /// An array of AND triples.
    pub auth_triples: Vec<AuthTriple>,
}

impl Fpre {
    /// Creates a new Fpre with random `delta_a`, `delta_b`.
    pub fn new(seed: u64, num_input_wires: usize, num_and_gates: usize) -> Self {
        let mut rng = ChaCha12Rng::seed_from_u64(seed);

        let delta_a = Delta::random(&mut rng);
        let delta_b = Delta::random(&mut rng);

        Self {
            rng,
            num_input_wires,
            num_and_gates,
            delta_a,
            delta_b,
            auth_bits: Vec::new(),
            auth_triples: Vec::new(),
        }
    }

    /// Generates an `AuthBit` for a single wire bit.
    pub fn gen_auth_bit(&mut self, x: bool) -> AuthBit {
        
        let r = self.rng.gen_bool(0.5);
        let s = x ^ r;
        // Build each share with the appropriate delta
        let r_share = build_share(&mut self.rng, r, &self.delta_b);
        let s_share = build_share(&mut self.rng, s, &self.delta_a);

        AuthBit {
            gen_share: AuthBitShare{ mac: r_share.mac, key: s_share.key},
            eval_share: AuthBitShare{mac: s_share.mac, key: r_share.key},
        }
    }

    /// Generates an `AuthTriple` for a single AND gate.
    pub fn gen_auth_triple(&mut self) -> AuthTriple {
        let x = self.rng.gen_bool(0.5);
        let y = self.rng.gen_bool(0.5);
        let z = x && y;

        AuthTriple {
            x: self.gen_auth_bit(x),
            y: self.gen_auth_bit(y),
            z: self.gen_auth_bit(z),
        }
    }

    /// Generates:
    /// 1. `auth_bits` for all wires (input + AND-output)
    /// 2. `auth_triples` for each AND gate
    /// Each share is built with `key.auth(bit, &delta)`.
    pub fn generate(&mut self) {
        // 1) Fill `auth_bits`
        let total_wire_bits = self.num_input_wires + self.num_and_gates;
        self.auth_bits.reserve(total_wire_bits);

        for _ in 0..total_wire_bits {
            // The “full bit”
            let x = self.rng.gen_bool(0.5);
            let auth_bit = self.gen_auth_bit(x);
            self.auth_bits.push(auth_bit);
        }

        // 2) Fill `auth_triples`
        self.auth_triples.reserve(self.num_and_gates);

        for _ in 0..self.num_and_gates {
            let triple = self.gen_auth_triple();
            self.auth_triples.push(triple);
        }
    }
    
    /// Returns a reference to the delta_a.
    pub fn delta_a(&self) -> &Delta {
        &self.delta_a
    }

    /// Returns a reference to the delta_b.
    pub fn delta_b(&self) -> &Delta {
        &self.delta_b
    }
}

/// The generator's view of the Fpre data.
#[derive(Debug)]
pub struct FpreGen {
    pub num_input_wires: usize,
    pub num_and_gates: usize,

    /// Possibly the generator knows `delta_a`, or if your design says generator
    /// knows `delta_b`, then store that here instead. 
    pub delta_a: Delta,

    /// The generator's share of each wire bit.
    /// e.g., for wire i, this is `auth_bits[i].gen_share`.
    pub wire_shares: Vec<AuthBitShare>,

    /// The generator's share of each triple: (x_gen, y_gen, z_gen).
    pub triple_shares: Vec<AuthTripleShare>,
}

/// The evaluator's view of the Fpre data.
#[derive(Debug)]
pub struct FpreEval {
    pub num_input_wires: usize,
    pub num_and_gates: usize,

    /// Possibly the evaluator knows `delta_b`, or if your design says evaluator
    /// knows `delta_a`, store that here. 
    pub delta_b: Delta,

    /// The evaluator's share of each wire bit.
    pub wire_shares: Vec<AuthBitShare>,

    /// The evaluator's share of each triple: (x_eval, y_eval, z_eval).
    pub triple_shares: Vec<AuthTripleShare>,
}

/// Methods to extract `FpreGen` and `FpreEval` from an `Fpre`.
impl Fpre {
    /// Extract the generator's portion of the Fpre data.
    pub fn to_generator(&self) -> FpreGen {

        // Collect the generator side of each wire
        let wire_shares = self
            .auth_bits
            .iter()
            .map(|wire| wire.gen_share.clone())
            .collect();

        // Collect the generator side of each triple
        let triple_shares = self
            .auth_triples
            .iter()
            .map(|t| AuthTripleShare {
                x: t.x.gen_share.clone(),
                y: t.y.gen_share.clone(),
                z: t.z.gen_share.clone(),
            })
            .collect();

        FpreGen {
            num_input_wires: self.num_input_wires,
            num_and_gates: self.num_and_gates,

            // If the generator is supposed to know delta_a or delta_b, choose accordingly:
            delta_a: self.delta_a.clone(),

            wire_shares,
            triple_shares,
        }
    }

    /// Extract the evaluator's portion of the Fpre data.
    pub fn to_evaluator(&self) -> FpreEval {
        let wire_shares = self
            .auth_bits
            .iter()
            .map(|wire| wire.eval_share.clone())
            .collect();

        let triple_shares = self
            .auth_triples
            .iter()
            .map(|t| AuthTripleShare {
                x: t.x.eval_share.clone(),
                y: t.y.eval_share.clone(),
                z: t.z.eval_share.clone(),
            })
            .collect();

        FpreEval {
            num_input_wires: self.num_input_wires,
            num_and_gates: self.num_and_gates,

            delta_b: self.delta_b.clone(),

            wire_shares,
            triple_shares,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use super::*;

    /// Checks that `share.mac == share.key.auth(share.bit, delta)`.
    fn check_share(share: &AuthBitShare, delta: &Delta) {
        let want = share.key.auth(share.bit(), delta);
        assert_eq!(share.mac, want, "MAC mismatch in share");
    }

    /// Checks one wire `AuthBit`:
    ///  - For generator: `check_share(bit.gen_share, delta_b)`  
    ///  - For evaluator: `check_share(bit.eval_share, delta_a)`  
    ///  - Ensures `full_bit = gen_share.bit ^ eval_share.bit`.
    fn check_auth_bit(bit: &AuthBit, delta_a: &Delta, delta_b: &Delta) {

        let r = AuthBitShare{mac: bit.gen_share.mac, key: bit.eval_share.key};
        let s = AuthBitShare{mac: bit.eval_share.mac, key: bit.gen_share.key};
        check_share(&r, delta_b);
        check_share(&s, delta_a);
    }

    /// Checks one `AuthTriple` as a whole, combining both parties:
    ///  1. Reconstruct x, y, z from gen/eval bits.
    ///  2. Confirm z = x & y (toy version).
    ///  3. Check generator's triple shares with `delta_b`.
    ///  4. Check evaluator's triple shares with `delta_a`.
    fn check_auth_triple(triple: &AuthTriple, delta_a: &Delta, delta_b: &Delta) {
        // 1) Reconstruct the full bits
        let x = triple.x.full_bit();
        let y = triple.y.full_bit();
        let z = triple.z.full_bit();

        // 2) Check z = x & y
        assert_eq!(z, x && y, "z must be x & y in this toy example");

        check_auth_bit(&triple.x, delta_a, delta_b);
        check_auth_bit(&triple.y, delta_a, delta_b);
        check_auth_bit(&triple.z, delta_a, delta_b);
    }

    #[test]
    fn test_fpre_generate() {
        let num_input_wires = 10;
        let num_and_gates = 8;
        let mut fpre = Fpre::new(0xDEAD_BEEF, num_input_wires, num_and_gates);

        fpre.generate();

        // Quick checks on array sizes
        assert_eq!(fpre.auth_bits.len(), num_input_wires + num_and_gates);
        assert_eq!(fpre.auth_triples.len(), num_and_gates);

        // 1) Check each wire bit using `check_bit(...)`
        for bit in &fpre.auth_bits {
            check_auth_bit(bit, fpre.delta_a(), fpre.delta_b());
        }

        // 2) Check each triple using `check_triple(...)`
        for triple in &fpre.auth_triples {
            check_auth_triple(triple, fpre.delta_a(), fpre.delta_b());
        }

        let fpre_gen = fpre.to_generator();
        let fpre_eval = fpre.to_evaluator();

        assert_eq!(fpre_gen.wire_shares.len(), num_input_wires + num_and_gates);
        assert_eq!(fpre_gen.triple_shares.len(), num_and_gates);

        assert_eq!(fpre_eval.wire_shares.len(), num_input_wires + num_and_gates);
        assert_eq!(fpre_eval.triple_shares.len(), num_and_gates);

        // // 3) Test FpreGen
        for (gen_wire_share, eval_wire_share) in zip(fpre_gen.wire_shares, fpre_eval.wire_shares) {
            let auth_bit = AuthBit {
                gen_share: gen_wire_share,
                eval_share: eval_wire_share,
            };
            check_auth_bit(&auth_bit, &fpre.delta_a, &fpre.delta_b);
        }

        for (gen_triple_share, eval_triple_share) in zip(fpre_gen.triple_shares, fpre_eval.triple_shares) {
            let auth_triple = AuthTriple {
                x: AuthBit {
                    gen_share: gen_triple_share.x,
                    eval_share: eval_triple_share.x,
                },
                y: AuthBit {
                    gen_share: gen_triple_share.y,
                    eval_share: eval_triple_share.y,
                },
                z: AuthBit {
                    gen_share: gen_triple_share.z,
                    eval_share: eval_triple_share.z,
                },
            };
            check_auth_triple(&auth_triple, &fpre.delta_a, &fpre.delta_b);
        }
    }
}
