//! Precomputed protocol configurations.

use crypto_bigint::BoxedUint;

use crate::dhim::crt::CrtSystem;

pub mod p256;

/// A concrete parameter set — one row of Table 5.16. Fixes the field size `|q|`
/// and statistical-security parameter `κ_s`, and records the derived
/// bit-lengths of the random-prime search range `s_r`, the sender/receiver
/// randomization domains `s_a`/`s_x`, and the smooth modulus `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `|q|` — bit length of the field modulus `q`.
    pub q_bits: u32,
    /// `κ_s` — statistical security parameter.
    pub kappa_s: u32,
    /// `s_r` — bit length of the random-prime search range.
    pub s_r_bits: u32,
    /// `|s_a|` — bit length of the sender's randomization domain.
    pub s_a_bits: u32,
    /// `|s_x|` — bit length of the receiver's randomization domain.
    pub s_x_bits: u32,
    /// `|n|` — bit length of the smooth modulus `n`.
    pub n_bits: u32,
}

/// A precomputed protocol configuration for one field.
#[derive(Clone, Copy)]
pub struct Config {
    /// The Table-5.16 parameters for this field size.
    pub params: Params,
    /// The CRT system.
    pub(crate) crt: &'static CrtSystem,
    /// The field modulus `q`.
    pub q: &'static BoxedUint,
    /// The fixed receiver-consistency prime `p` (Protocol 5.14): used for the
    /// malicious-receiver check. A prime `≥ 2^{κs+3}`, coprime to `q`
    /// and the CRT primes.
    pub p: &'static BoxedUint,
}
