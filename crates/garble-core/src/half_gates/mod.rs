//! Half-Gates garbling scheme implementation
//!
//! This module implements the "Two Halves Make a Whole" garbling scheme from
//! [Zahur, Rosulek, Evans 2015](https://eprint.iacr.org/2014/756).
//!
//! ## Overview
//!
//! The half-gates scheme reduces the size of garbled AND gates from 4
//! ciphertexts (classical garbled circuits) to **2 ciphertexts** (2κ bits,
//! where κ=128).
//!
//! ## Key Features
//!
//! - **AND gate size**: 2κ bits (32 bytes) per gate
//! - **Free XOR**: XOR gates have zero cost (no ciphertext)
//! - **Point-and-permute**: Fast evaluation using LSB color bits
//!
//! ## Architecture
//!
//! - [`Garbler`] - Generates garbled circuits and wire labels
//! - [`Evaluator`] - Evaluates garbled circuits using active wire labels

pub(crate) mod circuit;
pub(crate) mod evaluator;
pub(crate) mod garbler;

#[cfg(test)]
mod tests;

pub use circuit::{EncryptedGate, EncryptedGateBatch, GarbledCircuit};
pub use evaluator::{
    EncryptedGateBatchConsumer, EncryptedGateConsumer, Evaluator, EvaluatorError, EvaluatorOutput,
    EvaluatorWorker, evaluate_garbled_circuits,
};
pub use garbler::{
    EncryptedGateBatchIter, EncryptedGateIter, Garbler, GarblerError, GarblerOutput, GarblerWorker,
};
