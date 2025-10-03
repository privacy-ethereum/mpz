//! Copies of EvaluatorStore and GarblerStore with minimal modifications to
//! remove all cryptography operations.
//!
//! Places in the code which were changed are marked with // CHANGED

mod evaluator;
mod garbler;

pub(crate) use crate::store::mock::{
    evaluator::{EvaluatorStore, EvaluatorStoreError},
    garbler::{GarblerStore, GarblerStoreError},
};
