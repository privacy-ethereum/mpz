//! Boolean predicates over byte data.
//!
//! This module provides types for building and evaluating boolean predicates
//! that operate on byte arrays. Predicates can be:
//!
//! - Compiled into boolean circuits (see [`compiler::Compiler`])
//! - Evaluated directly via [`eval_pred`]
//!
//! # Building predicates
//!
//! Use helper functions to create atomic comparisons, and combine them with
//! [`Pred::and`], [`Pred::or`], and [`Pred::not`]:
//!
//! ```ignore
//! use mpz_predicate::{Pred, lt, eq, gte};
//!
//! // data[0] < data[1] AND data[2] == 42
//! let pred = Pred::and(vec![
//!     lt(0, 1),      // data[0] < data[1] (compare two indices)
//!     eq(2, 42u8),   // data[2] == 42 (compare index to constant)
//! ]);
//!
//! // NOT (data[3] >= 0x80)
//! let ascii_check = Pred::not(gte(3, 0x80u8));
//! ```
//!
//! # Comparison helpers
//!
//! Each helper takes an index and an operand. The operand can be:
//! - `usize` - compare with byte at another index
//! - `u8` - compare with a constant value
//!
//! Available comparisons:
//! - [`eq`] - equal (`==`)
//! - [`ne`] - not equal (`!=`)
//! - [`lt`] - less than (`<`)
//! - [`lte`] - less than or equal (`<=`)
//! - [`gt`] - greater than (`>`)
//! - [`gte`] - greater than or equal (`>=`)

pub mod compiler;
pub mod http;
pub mod json;

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use std::rc::Rc;

/// Predicate handle with structural sharing.
///
/// Predicates are reference-counted to allow efficient sharing of common
/// subexpressions. Use [`Pred::and`], [`Pred::or`], [`Pred::not`] to combine
/// predicates, and helper functions like [`eq`], [`lt`], etc. to create
/// atomic comparisons.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pred(Rc<PredNode>);

/// Internal predicate node representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PredNode {
    And(Vec<Pred>),
    Or(Vec<Pred>),
    Not(Pred),
    Atom(Atom),
}

impl Pred {
    /// Creates a conjunction (AND) of predicates.
    ///
    /// Returns true if all children are true.
    pub fn and(children: Vec<Pred>) -> Pred {
        Pred(Rc::new(PredNode::And(children)))
    }

    /// Creates a disjunction (OR) of predicates.
    ///
    /// Returns true if any child is true.
    pub fn or(children: Vec<Pred>) -> Pred {
        Pred(Rc::new(PredNode::Or(children)))
    }

    /// Creates a negation (NOT) of a predicate.
    pub fn not(child: Pred) -> Pred {
        Pred(Rc::new(PredNode::Not(child)))
    }

    /// Creates an atomic predicate from a comparison.
    ///
    /// Prefer using helper functions like [`eq`], [`lt`], etc. instead.
    pub(crate) fn atom(atom: Atom) -> Pred {
        Pred(Rc::new(PredNode::Atom(atom)))
    }

    /// Returns sorted unique byte indices referenced by this predicate.
    pub fn indices(&self) -> Vec<usize> {
        let mut collected = BTreeSet::new();
        let mut visited = std::collections::HashSet::new();
        collect_indices(self, &mut collected, &mut visited);
        collected.into_iter().collect()
    }

    /// Returns the raw pointer address for use as a cache key.
    pub(crate) fn ptr_key(&self) -> usize {
        Rc::as_ptr(&self.0) as usize
    }
}

// ============================================================================
// Comparison helper functions
// ============================================================================

/// Creates an equality predicate: `data[index] == rhs`.
pub fn eq(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Eq,
        rhs: rhs.into().0,
    })
}

/// Creates a not-equal predicate: `data[index] != rhs`.
pub fn ne(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Ne,
        rhs: rhs.into().0,
    })
}

/// Creates a less-than predicate: `data[index] < rhs`.
pub fn lt(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Lt,
        rhs: rhs.into().0,
    })
}

/// Creates a less-than-or-equal predicate: `data[index] <= rhs`.
pub fn lte(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Lte,
        rhs: rhs.into().0,
    })
}

/// Creates a greater-than predicate: `data[index] > rhs`.
pub fn gt(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Gt,
        rhs: rhs.into().0,
    })
}

/// Creates a greater-than-or-equal predicate: `data[index] >= rhs`.
pub fn gte(index: usize, rhs: impl Into<Operand>) -> Pred {
    Pred::atom(Atom {
        index,
        op: CmpOp::Gte,
        rhs: rhs.into().0,
    })
}

// ============================================================================
// Operand type for ergonomic API
// ============================================================================

/// Wrapper for comparison operand, enabling ergonomic API.
///
/// This type is not meant to be used directly. Instead, pass `usize` (for
/// index comparison) or `u8` (for constant comparison) to helper functions.
pub struct Operand(Rhs);

impl From<usize> for Operand {
    /// Compare with byte at another index.
    fn from(idx: usize) -> Self {
        Operand(Rhs::Idx(idx))
    }
}

impl From<u8> for Operand {
    /// Compare with a constant byte value.
    fn from(val: u8) -> Self {
        Operand(Rhs::Const(val))
    }
}

impl Pred {
    /// Returns a reference to the inner node (internal use only).
    pub(crate) fn inner(&self) -> &PredNode {
        &self.0
    }
}

impl fmt::Display for Pred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_indent(f, 0)
    }
}

impl Pred {
    fn fmt_with_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        fn pad(f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
            write!(f, "{:indent$}", "", indent = indent * 2)
        }

        match self.inner() {
            PredNode::And(preds) => {
                pad(f, indent)?;
                writeln!(f, "And(")?;
                for p in preds {
                    p.fmt_with_indent(f, indent + 1)?;
                }
                pad(f, indent)?;
                writeln!(f, ")")
            }
            PredNode::Or(preds) => {
                pad(f, indent)?;
                writeln!(f, "Or(")?;
                for p in preds {
                    p.fmt_with_indent(f, indent + 1)?;
                }
                pad(f, indent)?;
                writeln!(f, ")")
            }
            PredNode::Not(p) => {
                pad(f, indent)?;
                writeln!(f, "Not(")?;
                p.fmt_with_indent(f, indent + 1)?;
                pad(f, indent)?;
                writeln!(f, ")")
            }
            PredNode::Atom(a) => {
                pad(f, indent)?;
                writeln!(f, "Atom({:?})", a)
            }
        }
    }
}

/// Atomic predicate of the form: `data[index] op rhs`.
///
/// This is an internal type. Use helper functions like [`eq`], [`lt`], etc.
/// to create predicates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct Atom {
    pub(crate) index: usize,
    pub(crate) op: CmpOp,
    pub(crate) rhs: Rhs,
}

/// Comparison operator for atomic predicates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum CmpOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

/// Right-hand side of a comparison (internal).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) enum Rhs {
    /// Byte at index.
    Idx(usize),
    /// Literal constant.
    Const(u8),
}

/// Evaluates the predicate on the input `data`.
pub(crate) fn eval_pred(pred: &Pred, data: &[u8]) -> bool {
    match pred.inner() {
        PredNode::And(vec) => vec.iter().map(|p| eval_pred(p, data)).all(|b| b),
        PredNode::Or(vec) => vec.iter().map(|p| eval_pred(p, data)).any(|b| b),
        PredNode::Not(p) => !eval_pred(p, data),
        PredNode::Atom(atom) => {
            let lhs = data[atom.index];
            let rhs = match atom.rhs {
                Rhs::Const(c) => c,
                Rhs::Idx(s) => data[s],
            };
            match atom.op {
                CmpOp::Eq => lhs == rhs,
                CmpOp::Ne => lhs != rhs,
                CmpOp::Lt => lhs < rhs,
                CmpOp::Lte => lhs <= rhs,
                CmpOp::Gt => lhs > rhs,
                CmpOp::Gte => lhs >= rhs,
            }
        }
    }
}

/// Recursively collects byte indices from atoms in the predicate tree.
///
/// # Arguments
/// * `collected` - accumulates the byte indices found in atoms
/// * `visited` - tracks visited predicate nodes (by pointer) to avoid redundant
///   traversal
fn collect_indices(
    pred: &Pred,
    collected: &mut BTreeSet<usize>,
    visited: &mut std::collections::HashSet<usize>,
) {
    let key = pred.ptr_key();
    if !visited.insert(key) {
        return;
    }

    match pred.inner() {
        PredNode::And(vec) | PredNode::Or(vec) => {
            for p in vec {
                collect_indices(p, collected, visited);
            }
        }
        PredNode::Not(p) => collect_indices(p, collected, visited),
        PredNode::Atom(atom) => {
            collected.insert(atom.index);
            if let Rhs::Idx(idx) = atom.rhs {
                collected.insert(idx);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_and() {
        // data[0] < data[2] AND data[1] == 2
        let pred = Pred::and(vec![lt(0, 2usize), eq(1, 2u8)]);

        assert_eq!(eval_pred(&pred, &[1u8, 2, 3]), true);
        assert_eq!(eval_pred(&pred, &[1u8, 3, 3]), false);
    }

    #[test]
    fn test_or() {
        // data[0] < data[2] OR data[1] == 2
        let pred = Pred::or(vec![lt(0, 2usize), eq(1, 2u8)]);

        assert_eq!(eval_pred(&pred, &[1u8, 0, 3]), true); // first condition true
        assert_eq!(eval_pred(&pred, &[1u8, 3, 0]), false); // both false
    }

    #[test]
    fn test_not() {
        // NOT (data[0] < data[1])
        let pred = Pred::not(lt(0, 1usize));

        assert_eq!(eval_pred(&pred, &[5u8, 3]), true); // 5 < 3 is false, NOT false = true
        assert_eq!(eval_pred(&pred, &[1u8, 3]), false); // 1 < 3 is true, NOT
                                                        // true = false
    }

    #[test]
    fn test_rhs_const() {
        // data[0] < 22
        let pred = lt(0, 22u8);

        assert_eq!(eval_pred(&pred, &[5u8]), true);
        assert_eq!(eval_pred(&pred, &[23u8]), false);
    }

    #[test]
    fn test_rhs_idx() {
        // data[0] < data[1]
        let pred = lt(0, 1usize);

        assert_eq!(eval_pred(&pred, &[5u8, 10u8]), true);
        assert_eq!(eval_pred(&pred, &[23u8, 5u8]), false);
    }

    #[test]
    fn test_same_idx() {
        // data[0] == data[0] (always true)
        let pred1 = eq(0, 0usize);
        // data[0] < data[0] (always false)
        let pred2 = lt(0, 0usize);

        assert_eq!(eval_pred(&pred1, &[5u8]), true);
        assert_eq!(eval_pred(&pred2, &[5u8]), false);
    }

    #[test]
    fn test_eq() {
        // data[0] == data[1]
        let pred = eq(0, 1usize);

        assert_eq!(eval_pred(&pred, &[5u8, 5]), true);
        assert_eq!(eval_pred(&pred, &[1u8, 3]), false);
    }

    #[test]
    fn test_ne() {
        // data[0] != data[1]
        let pred = ne(0, 1usize);

        assert_eq!(eval_pred(&pred, &[5u8, 6]), true);
        assert_eq!(eval_pred(&pred, &[1u8, 1]), false);
    }

    #[test]
    fn test_gt() {
        // data[0] > data[1]
        let pred = gt(0, 1usize);

        assert_eq!(eval_pred(&pred, &[7u8, 6]), true);
        assert_eq!(eval_pred(&pred, &[1u8, 1]), false);
    }

    #[test]
    fn test_gte() {
        // data[0] >= data[1]
        let pred = gte(0, 1usize);

        assert_eq!(eval_pred(&pred, &[7u8, 7]), true);
        assert_eq!(eval_pred(&pred, &[0u8, 1]), false);
    }

    #[test]
    fn test_lt() {
        // data[0] < data[1]
        let pred = lt(0, 1usize);

        assert_eq!(eval_pred(&pred, &[2u8, 7]), true);
        assert_eq!(eval_pred(&pred, &[4u8, 1]), false);
    }

    #[test]
    fn test_lte() {
        // data[0] <= data[1]
        let pred = lte(0, 1usize);

        assert_eq!(eval_pred(&pred, &[2u8, 2]), true);
        assert_eq!(eval_pred(&pred, &[4u8, 1]), false);
    }
}
