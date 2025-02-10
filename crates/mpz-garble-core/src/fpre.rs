// fpre.rs

// TODO: Move auth bits and auth triples into correlated.rs
// TODO: Implement Delta/Block/Key/Mac arithmetic

use std::ops::Add;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use mpz_memory_core::correlated::{Delta, Key, Mac};

use mpz_ot_core::ideal::cot::IdealCOT;
use mpz_ot_core::cot::{COTSenderOutput, COTReceiverOutput};
use mpz_core::Block;

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

static SELECT_MASK: [Block; 2] = [Block::ZERO, Block::ONES];

// insecure hash function
fn h2d(a: Block, b: Block) -> Block {
    let mut d = [a, a ^ b];
    d[0] = d[0] ^ d[1]; 
    return d[0] ^ b;
}

// insecure hash function
fn h2(a: Block, b: Block) -> Block {
    let mut d = [a, b];
    d[0] = d[0] ^ d[1];
    d[0] = d[0] ^ a;
    return d[0] ^ b;
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
            leaky_shares: Vec::new(),
            location: Vec::new(),
        };

        let eval = FpreEval {
            num_input: self.num_input,
            num_and: self.num_and,
            delta_b: self.delta_b,
            wire_shares: eval_wire_shares,
            triple_shares: eval_triple_shares,
            leaky_shares: Vec::new(),
            location: Vec::new(),
        };

        (gen, eval)
    }
}



/// Fpre data from the generator's perspective.
#[derive(Debug)]
pub struct FpreGen {
    pub num_input: usize,
    pub num_and: usize,
    pub delta_a: Delta,
    pub wire_shares: Vec<AuthBitShare>,
    pub triple_shares: Vec<AuthTripleShare>,
    pub leaky_shares: Vec<AuthTripleShare>,
    pub location: Vec<usize>,
}

impl FpreGen {
    pub fn new(num_input: usize, num_and: usize, delta_a: Delta) -> Self {
        Self {
            num_input,
            num_and,
            delta_a,
            wire_shares: Vec::new(),
            triple_shares: Vec::new(),
            leaky_shares: Vec::new(),
            location: Vec::new(),
        }
    }

    fn set_bits(&mut self, auth_bits: Vec<AuthBitShare>) {
        self.wire_shares = auth_bits;
    }

    fn set_faulty_triples(&mut self, auth_bits: Vec<AuthBitShare>) {
        let length = auth_bits.len() / 3;
        for i in 0..length {
            self.leaky_shares.push(AuthTripleShare {
                x: auth_bits[3 * i].clone(),
                y: auth_bits[3 * i + 1].clone(),
                z: auth_bits[3 * i + 2].clone(),
            });
        }
    }

    fn triple_check_1(&mut self) -> (Vec<Block>, Vec<Block>) {
        let length = self.leaky_shares.len();
        let mut c = vec![Block::ZERO; length];
        let mut g = vec![Block::ZERO; length];

        for i in 0..length {
            c[i] = self.leaky_shares[i].y.mac.as_block().clone()
                ^ self.leaky_shares[i].y.key.as_block().clone()
                ^ (SELECT_MASK[self.leaky_shares[i].y.bit() as usize] & self.delta_a.as_block());

            g[i] = c[i] ^ h2d(self.leaky_shares[i].x.key.into(), self.delta_a.into_inner());
        }
        (c, g)
    }

    fn triple_check_2(&mut self, c: Vec<Block>, g: &mut Vec<Block>, gr: Vec<Block>) -> Vec<bool> {
        let length = self.leaky_shares.len();
        let mut d = vec![false; length];

        for i in 0..length {
            let mut s = h2(self.leaky_shares[i].x.mac.as_block().clone(), self.leaky_shares[i].x.key.as_block().clone());
            s = s ^ self.leaky_shares[i].z.mac.as_block().clone() ^ self.leaky_shares[i].z.key.as_block().clone();
            s = s ^ SELECT_MASK[self.leaky_shares[i].x.bit() as usize] & (gr[i] ^ c[i]);
            g[i] = s ^ SELECT_MASK[self.leaky_shares[i].z.bit() as usize] & self.delta_a.as_block();
            d[i] = g[i].second_lsb();
        }

        return d;
    }

    fn triple_check_3(&mut self, g: &mut Vec<Block>, mut d: Vec<bool>, dr: Vec<bool>) {
        let mut one: Block = Block::ZERO;
        one.set_lsb(true);

        let length = self.leaky_shares.len();
        for i in 0..length {
            d[i] = d[i] ^ dr[i];
            if d[i] {
                self.leaky_shares[i].z.mac = self.leaky_shares[i].z.mac + Mac::from(one);
                g[i] = g[i] ^ self.delta_a.as_block();
            }
        }
    }

    fn triple_combine_1(
        self: &Self,
        seed: u64,
        bucket_size: usize,
    ) -> Vec<bool> {
        let total = self.leaky_shares.len();
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;
    
        // Fisher–Yates shuffle in place
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut location: Vec<usize> = (0..total).collect();
        for i in (0..total).rev() {
            let idx = rng.gen_range(0..=i);
            location.swap(i, idx);
        }
    
        let mut data = vec![false; total];
    
        for i in 0..n {
            let base_idx = location[i*bucket_size + 0];    
            let y_base = self.leaky_shares[base_idx].y.bit();
    
            for j in 1..bucket_size {
                let idx_j = location[i*bucket_size + j];
                let y_j = self.leaky_shares[idx_j].y.bit();
                data[i*bucket_size + j] = y_base ^ y_j;
            }
        }
        data
    }

    fn triple_combine_2(
        self: &mut Self,
        seed: u64,
        bucket_size: usize,
        data: Vec<bool>,
        data_recv: Vec<bool>,
    ) {

        let total = self.leaky_shares.len();
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;
        
        // Fisher–Yates shuffle in place
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut location: Vec<usize> = (0..total).collect();
        for i in (0..total).rev() {
            let idx = rng.gen_range(0..=i);
            location.swap(i, idx);
        }

        let mut final_data = vec![false; total];
        for i in 0..total {
            final_data[i] = data[i] ^ data_recv[i];
        }
    
        for i in 0..n {
            let base_idx = location[i*bucket_size + 0];
    
            // Start with a "copy" of the first triple in the bucket
            let mut combined_share = self.leaky_shares[base_idx].clone();
    
            // For j in [1..bucket_size], merge x and z wires, keep y same as base
            for j in 1..bucket_size {
                let idx_j = location[i*bucket_size + j];
    
                combined_share.x = combined_share.x + self.leaky_shares[idx_j].x;
    
                combined_share.z = combined_share.z + self.leaky_shares[idx_j].z;
    
                // If d == 1, correct z-wire by xoring with x-wire
                if final_data[i*bucket_size + j] {
                    combined_share.z = combined_share.z + self.leaky_shares[idx_j].x;
                }
            }
            self.triple_shares.push(combined_share);
        }
    }
}


/// Fpre data from the evaluator's perspective.
#[derive(Debug)]
pub struct FpreEval {
    pub num_input: usize,
    pub num_and: usize,
    pub delta_b: Delta,
    pub wire_shares: Vec<AuthBitShare>,
    pub triple_shares: Vec<AuthTripleShare>,
    pub leaky_shares: Vec<AuthTripleShare>,
    pub location: Vec<usize>,
}

impl FpreEval {
    pub fn new(num_input: usize, num_and: usize, delta_b: Delta) -> Self {
        Self {
            num_input,
            num_and,
            delta_b,
            wire_shares: Vec::new(),
            triple_shares: Vec::new(),
            leaky_shares: Vec::new(),
            location: Vec::new(),
        }   
    }

    fn set_bits(&mut self, auth_bits: Vec<AuthBitShare>) {
        self.wire_shares = auth_bits;
    }

    fn set_faulty_triples(&mut self, auth_bits: Vec<AuthBitShare>) {
        let length = auth_bits.len() / 3;
        for i in 0..length {
            self.leaky_shares.push(AuthTripleShare {
                x: auth_bits[3 * i].clone(),
                y: auth_bits[3 * i + 1].clone(),
                z: auth_bits[3 * i + 2].clone(),
            });
        }
    }

    fn triple_check_1(&mut self) -> (Vec<Block>, Vec<Block>) {
        let length = self.leaky_shares.len();
        let mut c = vec![Block::ZERO; length];
        let mut g = vec![Block::ZERO; length];

        for i in 0..length {
            c[i] = self.leaky_shares[i].y.mac.as_block().clone()
                ^ self.leaky_shares[i].y.key.as_block().clone()
                ^ (SELECT_MASK[self.leaky_shares[i].y.bit() as usize] & self.delta_b.as_block());

            g[i] = c[i] ^ h2d(self.leaky_shares[i].x.key.into(), self.delta_b.into_inner());
        }
        (c, g)
    }

    fn triple_check_2(&mut self, c: Vec<Block>, g: &mut Vec<Block>, gr: Vec<Block>) -> Vec<bool> {
        let length = self.leaky_shares.len();
        let mut d = vec![false; length];

        for i in 0..length {
            let mut s = h2(self.leaky_shares[i].x.mac.as_block().clone(), self.leaky_shares[i].x.key.as_block().clone());
            s = s ^ self.leaky_shares[i].z.mac.as_block().clone() ^ self.leaky_shares[i].z.key.as_block().clone();
            s = s ^ SELECT_MASK[self.leaky_shares[i].x.bit() as usize] & (gr[i] ^ c[i]);
            g[i] = s ^ SELECT_MASK[self.leaky_shares[i].z.bit() as usize] & self.delta_b.as_block();
            d[i] = g[i].second_lsb();
        }

        return d;

    }

    fn triple_check_3(&mut self, g: &mut Vec<Block>, mut d: Vec<bool>, dr: Vec<bool>) {
        let mut zdelta_mask: Block = Block::ONES;
        zdelta_mask.set_lsb(false);
        let zdelta = self.delta_b.as_block() & zdelta_mask;

        let length = self.leaky_shares.len();
        for i in 0..length {
            d[i] = d[i] ^ dr[i];
            if d[i] {
                self.leaky_shares[i].z.key = self.leaky_shares[i].z.key + Key::from(zdelta);
                g[i] = g[i] ^ self.delta_b.as_block();
            }
        }
    }

    fn triple_combine_1(
        self: &Self,
        seed: u64,
        bucket_size: usize,
    ) -> Vec<bool> {
        let total = self.leaky_shares.len();
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;
    
        // Fisher–Yates shuffle in place
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut location: Vec<usize> = (0..total).collect();
        for i in (0..total).rev() {
            let idx = rng.gen_range(0..=i);
            location.swap(i, idx);
        }
    
        let mut data = vec![false; total];
    
        for i in 0..n {
            let base_idx = location[i*bucket_size + 0];    
            let y_base = self.leaky_shares[base_idx].y.bit();
    
            for j in 1..bucket_size {
                let idx_j = location[i*bucket_size + j];
                let y_j = self.leaky_shares[idx_j].y.bit();
                data[i*bucket_size + j] = y_base ^ y_j;
            }
        }
        data
    }

    fn triple_combine_2(
        self: &mut Self,
        seed: u64,
        bucket_size: usize,
        data: Vec<bool>,
        data_recv: Vec<bool>,
    ) {

        let total = self.leaky_shares.len();
        assert_eq!(total % bucket_size, 0,
            "total length must be multiple of bucket_size");
        let n = total / bucket_size;
        
        // Fisher–Yates shuffle in place
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut location: Vec<usize> = (0..total).collect();
        for i in (0..total).rev() {
            let idx = rng.gen_range(0..=i);
            location.swap(i, idx);
        }

        let mut final_data = vec![false; total];
        for i in 0..total {
            final_data[i] = data[i] ^ data_recv[i];
        }

        for i in 0..n {
            let base_idx = location[i*bucket_size + 0];
    
            // Start with a "copy" of the first triple in the bucket
            let mut combined_share = self.leaky_shares[base_idx].clone();
    
            // For j in [1..bucket_size], merge x and z wires, keep y same as base
            for j in 1..bucket_size {
                let idx_j = location[i*bucket_size + j];
    
                combined_share.x = combined_share.x + self.leaky_shares[idx_j].x;
    
                combined_share.z = combined_share.z + self.leaky_shares[idx_j].z;
    
                // If d == 1, correct z-wire by xoring with x-wire
                if final_data[i*bucket_size + j] {
                    combined_share.z = combined_share.z + self.leaky_shares[idx_j].x;
                }
            }
            self.triple_shares.push(combined_share);
        }
    }
}

/// Generate auth bit shares using ideal COT
fn bit_shares_from_cot(
    length: usize,
    delta_a: Delta,
    delta_b: Delta,
) -> Result<(Vec<AuthBitShare>, Vec<AuthBitShare>), FpreError> {

    let mut rng = ChaCha12Rng::seed_from_u64(0);

    // Perform COT with delta_b and eval keys so that received messages are macs on bits known to eval
    let mut cot_eval = IdealCOT::new(delta_b.into_inner());
    let gen_bits: Vec<bool> = (0..length).map(|_| rng.gen()).collect::<Vec<_>>();
    let eval_keys: Vec<Block> = (0..length).map(|_| rng.gen()).collect::<Vec<_>>();

    let (
        COTSenderOutput { id: _sender_id },
        COTReceiverOutput {
            id: _receiver_id,
            msgs: received,
        },
    ) = cot_eval.transfer(&gen_bits, &eval_keys).unwrap();

    let gen_macs = received;

    // Perform COT with delta_a and gen keys so that received messages are macs on bits known to gen
    let mut cot_gen = IdealCOT::new(delta_a.into_inner());
    let eval_bits: Vec<bool> = (0..length).map(|_| rng.gen()).collect::<Vec<_>>();
    let gen_keys: Vec<Block> = (0..length).map(|_| rng.gen()).collect::<Vec<_>>();

    let (
        COTSenderOutput { id: _sender_id },
        COTReceiverOutput {
            id: _receiver_id,
            msgs: received,
        },
    ) = cot_gen.transfer(&eval_bits, &gen_keys).unwrap();

    let eval_macs = received;

    // Construct auth bit shares from COT outputs
    let mut gen_shares: Vec<AuthBitShare> = Vec::with_capacity(length);
    let mut eval_shares: Vec<AuthBitShare> = Vec::with_capacity(length);

    for i in 0..length {
        let r = gen_bits[i];
        let mut m_r = gen_macs[i];
        m_r.set_lsb(r);

        let mut k_r = gen_keys[i];
        k_r.set_lsb(false);

        gen_shares.push(AuthBitShare {
            key: k_r.into(),
            mac: m_r.into(),
        });

        let s = eval_bits[i];
        let mut m_s = eval_macs[i];
        m_s.set_lsb(s);

        let mut k_s = eval_keys[i];
        k_s.set_lsb(false);

        eval_shares.push(AuthBitShare {
            key: k_s.into(),
            mac: m_s.into(),
        });
    }

    Ok((gen_shares, eval_shares))
    
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
    fn test_fpre_insecure() {
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

    #[test]
    fn test_fpre_bits() {
        let num_wires = 100;
        let num_and = 50;
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        // need to set second-LSB of deltas to XOR to 1 for an optimization
        let mut delta_a = Delta::random(&mut rng);
        delta_a.set_second_lsb(true);
        let mut delta_b = Delta::random(&mut rng);
        delta_b.set_second_lsb(false);

        let mut fpre_gen = FpreGen::new(num_wires, num_and, delta_a);
        let mut fpre_eval = FpreEval::new(num_wires, num_and, delta_b);

        let (gen_shares, eval_shares) = 
            bit_shares_from_cot(num_wires+num_and, delta_a, delta_b)
            .unwrap();

        fpre_gen.set_bits(gen_shares);
        fpre_eval.set_bits(eval_shares);

        for i in 0..num_wires+num_and {
            check_auth_bit(&AuthBit {
                gen_share: fpre_gen.wire_shares[i],
                eval_share: fpre_eval.wire_shares[i],
            }, &delta_a, &delta_b);
        }
    }

    #[test]
    fn test_fpre_triples() {
        let num_wires = 100;
        let num_and = 60;
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        // need to set second-LSB of deltas to XOR to 1 for an optimization
        let mut delta_a = Delta::random(&mut rng);
        delta_a.set_second_lsb(true);
        let mut delta_b = Delta::random(&mut rng);
        delta_b.set_second_lsb(false);

        let mut fpre_gen = FpreGen::new(num_wires, num_and, delta_a);
        let mut fpre_eval = FpreEval::new(num_wires, num_and, delta_b);

        let (gen_shares, eval_shares) = 
            bit_shares_from_cot(3*num_and, delta_a, delta_b)
            .unwrap();

        fpre_gen.set_faulty_triples(gen_shares);
        fpre_eval.set_faulty_triples(eval_shares);

        let (c_gen, mut g_gen) = fpre_gen.triple_check_1();
        let (c_eval, mut g_eval) = fpre_eval.triple_check_1();

        // First round of communication
        let gr_gen = g_eval.clone();
        let gr_eval = g_gen.clone();

        let d_gen = fpre_gen.triple_check_2(c_gen, &mut g_gen, gr_gen);
        let d_eval = fpre_eval.triple_check_2(c_eval, &mut g_eval, gr_eval);

        // Second round of communication
        let dr_gen = d_eval.clone();    
        let dr_eval = d_gen.clone();

        fpre_gen.triple_check_3(&mut g_gen, d_gen, dr_gen);
        fpre_eval.triple_check_3(&mut g_eval, d_eval, dr_eval);

        // Push to Feq here
        for (g_gen, g_eval) in zip(g_gen, g_eval) {
            assert_eq!(g_gen, g_eval);
        }

        let d_gen = fpre_gen.triple_combine_1(0xDEAD_BEEF, 5);
        let d_eval = fpre_eval.triple_combine_1( 0xDEAD_BEEF, 5);

        fpre_gen.triple_combine_2(0xDEAD_BEEF, 5, d_gen.clone(), d_eval.clone());
        fpre_eval.triple_combine_2(0xDEAD_BEEF, 5, d_eval.clone(), d_gen.clone());

        // Check new triples
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


// TODO: secure coin tossing and secure COT