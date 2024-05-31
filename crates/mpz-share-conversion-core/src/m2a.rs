//! M2A conversion protocol.
//!
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.

use mpz_fields::Field;

/// Converts output field elements of an OLE sender into additive shares.
///
/// # Arguments
///
/// * `shares` - Output from an OLE Sender.
pub fn m2a_convert<F: Field>(mut shares: Vec<F>) -> Vec<F> {
    shares.iter_mut().for_each(|s| *s = -*s);
    shares
}
