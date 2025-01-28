// fpre.rs

// TODO: Move auth bits and auth triples into correlated.rs
// TODO: Implement Delta/Block/Key/Mac arithmetic

use std::ops::Add;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use mpz_memory_core::correlated::{Delta, Key, Mac};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum FpreError {
    #[error("fpre not yet generated")]
    NotGenerated,
    #[error("invalid wire shares: have {0}, expected {1}")]
    InvalidWireCount(usize, usize),
    #[error("invalid triple shares: have {0}, expected {1}")]
    InvalidTripleCount(usize, usize),
}

/// (key, mac) pair with bit = mac.pointer()
#[derive(Debug, Clone, Default, Copy)]
pub struct AuthBitShare {
    pub key: Key,
    pub mac: Mac,
}

impl AuthBitShare {
    /// Retrieves the embedded bit from the LSB of `mac`.
    #[inline]
    pub fn bit(&self) -> bool {
        self.mac.pointer()
    }
}

impl Add<AuthBitShare> for AuthBitShare {
    type Output = Self;

    #[inline]
    fn add(self, rhs: AuthBitShare) -> Self {
        Self {
            key: self.key + rhs.key,
            mac: self.mac + rhs.mac,
        }
    }
}

impl Add<&AuthBitShare> for AuthBitShare {
    type Output = Self;

    #[inline]
    fn add(self, rhs: &AuthBitShare) -> Self {
        Self {
            key: self.key + rhs.key,
            mac: self.mac + rhs.mac,
        }
    }
}

impl Add<AuthBitShare> for &AuthBitShare {
    type Output = AuthBitShare;

    #[inline]
    fn add(self, rhs: AuthBitShare) -> AuthBitShare {
        AuthBitShare {
            key: self.key + rhs.key,
            mac: self.mac + rhs.mac,
        }
    }
}

impl Add<&AuthBitShare> for &AuthBitShare {
    type Output = AuthBitShare;

    #[inline]
    fn add(self, rhs: &AuthBitShare) -> AuthBitShare {
        AuthBitShare {
            key: self.key + rhs.key,
            mac: self.mac + rhs.mac,
        }
    }
}

/// Builds one `AuthBitShare` from a boolean bit and delta, ensuring `key.lsb()==false`.
fn build_share(rng: &mut ChaCha12Rng, bit: bool, delta: &Delta) -> AuthBitShare {
    let mut key: Key = rng.gen();
    key.set_pointer(false);
    let mac = key.auth(bit, delta);
    AuthBitShare { key, mac }
}

/// Represents an auth bit [x] = [r]+[s] where [r] is known to gen, auth by eval and [s] is known to eval, auth by gen.
#[derive(Debug, Clone)]
pub struct AuthBit {
    pub gen_share: AuthBitShare,  
    pub eval_share: AuthBitShare,
}

impl AuthBit {
    /// Recover the full bit x = r ^ s
    pub fn full_bit(&self) -> bool {
        self.gen_share.bit() ^ self.eval_share.bit()
    }
}

/// A triple ([x], [y], [z]) of auth bits such that z = x & y.
#[derive(Debug, Clone)]
pub struct AuthTriple {
    pub x: AuthBit,
    pub y: AuthBit,
    pub z: AuthBit,
}

/// Per-party triple share: x,y,z each an `AuthBitShare`.
#[derive(Debug, Clone)]
pub struct AuthTripleShare {
    pub x: AuthBitShare,
    pub y: AuthBitShare,
    pub z: AuthBitShare,
}

/// Insecure ideal Fpre that pre-generates auth bits for wires and auth triples for AND gates.
#[derive(Debug)]
pub struct Fpre {
    rng: ChaCha12Rng,
    num_input: usize,
    num_and: usize,

    /// Evaluator's global correlation
    delta_a: Delta,
    /// Generator's global correlation
    delta_b: Delta,

    /// Bits for wires (input + AND-output)
    pub auth_bits: Vec<AuthBit>,
    /// Triples for AND gates
    pub auth_triples: Vec<AuthTriple>,
}

impl Fpre {
    /// Creates a new Fpre with random `delta_a`, `delta_b`.
    pub fn new(seed: u64, num_input: usize, num_and: usize) -> Self {
        let mut rng = ChaCha12Rng::seed_from_u64(seed);

        let delta_a = Delta::random(&mut rng);
        let delta_b = Delta::random(&mut rng);

        Self {
            rng,
            num_input,
            num_and,
            delta_a,
            delta_b,
            auth_bits: Vec::new(),
            auth_triples: Vec::new(),
        }
    }

    /// Builds an AuthBit [x] from a bit b such that x=b 
    pub fn gen_auth_bit(&mut self, x: bool) -> AuthBit {
        
        let r = self.rng.gen_bool(0.5);
        let s = x ^ r;

        let r_share = build_share(&mut self.rng, r, &self.delta_b);
        let s_share = build_share(&mut self.rng, s, &self.delta_a);

        AuthBit {
            // Swapped key/mac for each share so that
            // gen knows mac from delta_b and key from delta_a, etc.
            gen_share: AuthBitShare{ mac: r_share.mac, key: s_share.key},
            eval_share: AuthBitShare{mac: s_share.mac, key: r_share.key},
        }
    }

    /// Builds a random triple
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

    /// Main Fpre generation: auth bits for wires (input + AND) and triples for AND gates
    pub fn generate(&mut self) {
        
        let total_wire_bits = self.num_input + self.num_and;
        self.auth_bits.reserve(total_wire_bits);
        for _ in 0..total_wire_bits {
            let x = self.rng.gen_bool(0.5);
            let auth_bit = self.gen_auth_bit(x);
            self.auth_bits.push(auth_bit);
        }

        self.auth_triples.reserve(self.num_and);
        for _ in 0..self.num_and {
            let triple = self.gen_auth_triple();
            self.auth_triples.push(triple);
        }
    }
    
    /// Returns a reference to the generator's global correlation.
    pub fn delta_a(&self) -> &Delta {
        &self.delta_a
    }

    /// Returns a reference to the evaluator's global correlation.
    pub fn delta_b(&self) -> &Delta {
        &self.delta_b
    }

    /// Consumes `self` to produce `(FpreGen, FpreEval)` ownership in one go.
    pub fn into_gen_eval(mut self) -> (FpreGen, FpreEval) {

        // Generator wire shares
        let gen_wire_shares = self.auth_bits
            .iter()
            .map(|bit| bit.gen_share.clone())
            .collect();

        // Evaluator wire shares
        let eval_wire_shares = self.auth_bits
            .drain(..) // consume them
            .map(|bit| bit.eval_share)
            .collect::<Vec<_>>();

        // Generator triple shares
        let gen_triple_shares = self.auth_triples
            .iter()
            .map(|t| AuthTripleShare {
                x: t.x.gen_share.clone(),
                y: t.y.gen_share.clone(),
                z: t.z.gen_share.clone(),
            })
            .collect();

        // Evaluator triple shares
        let eval_triple_shares = self.auth_triples
            .drain(..) // consume
            .map(|t| AuthTripleShare {
                x: t.x.eval_share,
                y: t.y.eval_share,
                z: t.z.eval_share,
            })
            .collect();

        let gen = FpreGen {
            num_input: self.num_input,
            num_and: self.num_and,
            delta_a: self.delta_a,
            wire_shares: gen_wire_shares,
            triple_shares: gen_triple_shares,
        };

        let eval = FpreEval {
            num_input: self.num_input,
            num_and: self.num_and,
            delta_b: self.delta_b,
            wire_shares: eval_wire_shares,
            triple_shares: eval_triple_shares,
        };

        (gen, eval)
    }
}



/// Fpre data from the generator’s perspective.
#[derive(Debug)]
pub struct FpreGen {
    pub num_input: usize,
    pub num_and: usize,
    pub delta_a: Delta,
    pub wire_shares: Vec<AuthBitShare>,
    pub triple_shares: Vec<AuthTripleShare>,
}

/// Fpre data from the evaluator’s perspective.
#[derive(Debug)]
pub struct FpreEval {
    pub num_input: usize,
    pub num_and: usize,
    pub delta_b: Delta,
    pub wire_shares: Vec<AuthBitShare>,
    pub triple_shares: Vec<AuthTripleShare>,
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

    fn check_auth_bit(bit: &AuthBit, delta_a: &Delta, delta_b: &Delta) {
        // Reconstruct shares for testing
        let r = AuthBitShare {
            mac: bit.gen_share.mac,
            key: bit.eval_share.key,
        };
        let s = AuthBitShare {
            mac: bit.eval_share.mac,
            key: bit.gen_share.key,
        };
        check_share(&r, delta_b);
        check_share(&s, delta_a);
    }

    fn check_auth_triple(triple: &AuthTriple, delta_a: &Delta, delta_b: &Delta) {
        let x = triple.x.full_bit();
        let y = triple.y.full_bit();
        let z = triple.z.full_bit();
        assert_eq!(z, x && y, "z must equal x & y");
        check_auth_bit(&triple.x, delta_a, delta_b);
        check_auth_bit(&triple.y, delta_a, delta_b);
        check_auth_bit(&triple.z, delta_a, delta_b);
    }

    #[test]
    fn test_fpre_generate() {
        let num_input = 10;
        let num_and = 8;
        let mut fpre = Fpre::new(0xDEAD_BEEF, num_input, num_and);
        fpre.generate();

        assert_eq!(fpre.auth_bits.len(), num_input + num_and);
        assert_eq!(fpre.auth_triples.len(), num_and);

        for bit in &fpre.auth_bits {
            check_auth_bit(bit, fpre.delta_a(), fpre.delta_b());
        }
        for triple in &fpre.auth_triples {
            check_auth_triple(triple, fpre.delta_a(), fpre.delta_b());
        }

        let (fpre_gen, fpre_eval) = fpre.into_gen_eval();

        // wire shares length
        assert_eq!(
            fpre_gen.wire_shares.len(),
            num_input + num_and
        );
        assert_eq!(
            fpre_eval.wire_shares.len(),
            num_input + num_and
        );

        // triple shares length
        assert_eq!(fpre_gen.triple_shares.len(), num_and);
        assert_eq!(fpre_eval.triple_shares.len(), num_and);

        // Check generator/evaluator shares align
        for (gen_share, eval_share) in zip(fpre_gen.wire_shares, fpre_eval.wire_shares) {
            let bit = AuthBit {
                gen_share,
                eval_share,
            };
            check_auth_bit(&bit, &fpre_gen.delta_a, &fpre_eval.delta_b);
        }

        for (gen_triple, eval_triple) in zip(fpre_gen.triple_shares, fpre_eval.triple_shares) {
            let triple = AuthTriple {
                x: AuthBit {
                    gen_share: gen_triple.x,
                    eval_share: eval_triple.x,
                },
                y: AuthBit {
                    gen_share: gen_triple.y,
                    eval_share: eval_triple.y,
                },
                z: AuthBit {
                    gen_share: gen_triple.z,
                    eval_share: eval_triple.z,
                },
            };
            check_auth_triple(&triple, &fpre_gen.delta_a, &fpre_eval.delta_b);
        }
    }
}
