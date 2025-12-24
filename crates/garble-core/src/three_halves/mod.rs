//! # Three Halves Make a Whole - Garbled Circuit Implementation
//!
//! This module implements the "Three Halves Make a Whole" garbling scheme from:
//!
//! **Paper**: "Three Halves Make a Whole? Beating the Half-Gates Lower Bound
//! for Garbled Circuits" **Authors**: Mike Rosulek, Lawrence Roy
//! **Published**: Eurocrypt 2021
//! **ePrint**: <https://eprint.iacr.org/2021/749>
//!
//! ## Overview
//!
//! This scheme reduces AND gate size from 2κ bits (half-gates) to 1.5κ + 5 bits
//! using two key techniques:
//!
//! 1. **Slicing**: Wire labels are split into left/right halves (κ/2 bits
//!    each), and the evaluator computes each half using potentially different
//!    linear combinations.
//!
//! 2. **Dicing**: The evaluator decrypts "control bits" that determine which
//!    linear combinations to apply. These control bits are randomized to hide
//!    the gate's truth table.
//!
//! ## Module Structure
//!
//! - [`matrices`]: Core matrices (K, V, M) that define the linear algebraic
//!   structure
//! - [`control`]: Control matrix system (R, S₁, S₂) for the "dicing" technique
//! - [`slicing`]: Wire label slicing utilities
//! - [`garbler`]: Garbling functions
//! - [`evaluator`]: Evaluation functions
//!
//! ## Usage
//!
//! ```ignore
//! use mpz_garble_core::three_halves::{Garbler, Evaluator, GarblerOutput, EvaluatorOutput};
//!
//! let mut gb = Garbler::default();
//! let mut ev = Evaluator::default();
//!
//! let mut gb_iter = gb.generate(&circuit, delta, &input_keys, &mut rng)?;
//! let mut ev_consumer = ev.evaluate(&circuit, &input_macs)?;
//!
//! while let Some(gate) = gb_iter.next() {
//!     ev_consumer.next(gate);
//! }
//!
//! let gb_output = gb_iter.finish()?;
//! let ev_output = ev_consumer.finish()?;
//! ```

pub(crate) mod circuit;
pub mod control;
pub mod evaluator;
pub mod garbler;
mod garbler_tables;
pub mod matrices;
mod random_bits;
pub mod slicing;

/// Gate ciphertexts for a Three Halves AND gate.
///
/// Contains 3 ciphertexts of κ/2 bits each = 1.5κ bits total.
/// This is smaller than half-gates which uses 2κ bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThreeHalvesGate {
    /// Gate ciphertext G₀ (κ/2 = 64 bits)
    pub g0: [u8; 8],
    /// Gate ciphertext G₁ (κ/2 = 64 bits)
    pub g1: [u8; 8],
    /// Gate ciphertext G₂ (κ/2 = 64 bits)
    pub g2: [u8; 8],
}

impl ThreeHalvesGate {
    /// Create a new gate from three κ/2-bit ciphertexts.
    pub fn new(g0: [u8; 8], g1: [u8; 8], g2: [u8; 8]) -> Self {
        Self { g0, g1, g2 }
    }
}

/// Control bits for evaluator (compressed form).
///
/// The r_bar is a 4×2 matrix where each row r_bar[ij] contains the coefficients
/// [c₁, c₂] for input position (i,j). The evaluator expands this to a 2×4
/// marginal using: R_ij = c₁·S₁ ⊕ c₂·S₂
///
/// Stored as a packed u8: bits [2*ij, 2*ij+1] hold [c₁, c₂] for position ij.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ControlBits(u8);

impl ControlBits {
    /// Create new control bits from the compressed r_bar representation.
    ///
    /// Packs the 4×2 matrix into a single byte.
    pub fn new(r_bar: [[u8; 2]; 4]) -> Self {
        let bits = (r_bar[0][0] & 1)
            | ((r_bar[0][1] & 1) << 1)
            | ((r_bar[1][0] & 1) << 2)
            | ((r_bar[1][1] & 1) << 3)
            | ((r_bar[2][0] & 1) << 4)
            | ((r_bar[2][1] & 1) << 5)
            | ((r_bar[3][0] & 1) << 6)
            | ((r_bar[3][1] & 1) << 7);
        Self(bits)
    }

    /// Get the coefficients [c₁, c₂] for input position (i, j).
    #[inline]
    pub fn get(&self, ij: usize) -> [u8; 2] {
        let shift = 2 * ij;
        [(self.0 >> shift) & 1, (self.0 >> (shift + 1)) & 1]
    }
}

// Re-export circuit types
pub use circuit::{EncryptedGate, EncryptedGateBatch, GarbledCircuit};

// Re-export main types from garbler
pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput,
};

// Re-export main types from evaluator
pub use evaluator::{
    EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator, EvaluatorError, EvaluatorOutput,
    evaluate_garbled_circuits,
};

#[cfg(test)]
mod tests;
