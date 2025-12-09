//! Compiles predicates into boolean circuits.
//!
//! The [`Compiler`] transforms a predicate tree into a circuit that can be
//! evaluated on byte data. Each byte index referenced in the predicate becomes
//! 8 input feeds (one per bit), and the circuit outputs a single bit indicating
//! whether the predicate is satisfied.

use std::collections::HashMap;

use mpz_circuits::{itybity::ToBits, ops, Circuit, CircuitBuilder, Feed, Node};

use crate::{CmpOp, Pred, PredNode, Rhs};

/// Compiles predicates into boolean circuits.
///
/// The compiler maintains internal state for mapping byte indices to circuit
/// feeds and caching processed predicate nodes to avoid redundant work.
pub struct Compiler {
    /// Maps byte indices to their 8-bit circuit feed representation.
    map: HashMap<usize, [Node<Feed>; 8]>,
    /// Caches processed predicate nodes by pointer address to avoid
    /// recomputation.
    cache: HashMap<usize, Node<Feed>>,
}

impl Compiler {
    /// Creates a new compiler instance.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Compiles a predicate into a boolean circuit.
    ///
    /// # Arguments
    /// * `pred` - The predicate to compile.
    ///
    /// # Returns
    /// A circuit with:
    /// - Inputs: 8 bits per unique byte index in the predicate (sorted order)
    /// - Output: Single bit indicating predicate satisfaction
    pub fn compile(&mut self, pred: &Pred) -> Circuit {
        let mut builder = CircuitBuilder::new();

        // Create 8-bit input feeds for each byte index referenced in the predicate
        for idx in pred.indices() {
            let feeds: Vec<_> = (0..8).map(|_| builder.add_input()).collect();
            self.map.insert(idx, feeds.try_into().unwrap());
        }

        let output = self.process(&mut builder, pred);

        builder.add_output(output);
        builder.build().unwrap()
    }

    /// Recursively processes a predicate node into circuit gates.
    ///
    /// # Arguments
    /// * `builder` - The circuit builder to add gates to.
    /// * `pred` - The predicate node to process.
    ///
    /// # Returns
    /// A feed node representing the predicate's boolean result.
    fn process(&mut self, builder: &mut CircuitBuilder, pred: &Pred) -> Node<Feed> {
        // Check cache to avoid reprocessing shared predicate nodes
        let key = pred.ptr_key();
        if let Some(&cached) = self.cache.get(&key) {
            return cached;
        }

        let result = match pred.inner() {
            PredNode::And(children) => {
                let outputs: Vec<_> = children.iter().map(|p| self.process(builder, p)).collect();
                ops::all(builder, &outputs)
            }
            PredNode::Or(children) => {
                let outputs: Vec<_> = children.iter().map(|p| self.process(builder, p)).collect();
                ops::any(builder, &outputs)
            }
            PredNode::Not(child) => {
                let child_out = self.process(builder, child);
                ops::inv(builder, [child_out])[0]
            }
            PredNode::Atom(atom) => {
                let lhs = self.map[&atom.index];
                let rhs = match atom.rhs {
                    Rhs::Const(c) => const_to_feeds(builder, c),
                    Rhs::Idx(idx) => self.map[&idx],
                };
                match atom.op {
                    CmpOp::Eq => ops::eq(builder, lhs, rhs),
                    CmpOp::Ne => ops::neq(builder, lhs, rhs),
                    CmpOp::Lt => ops::lt(builder, lhs, rhs),
                    CmpOp::Lte => ops::lte(builder, lhs, rhs),
                    CmpOp::Gt => ops::gt(builder, lhs, rhs),
                    CmpOp::Gte => ops::gte(builder, lhs, rhs),
                }
            }
        };

        self.cache.insert(key, result);
        result
    }
}

/// Converts a constant byte value to 8 circuit feed nodes.
///
/// # Arguments
/// * `builder` - The circuit builder to get constant nodes from.
/// * `value` - The byte value to convert.
///
/// # Returns
/// An array of 8 feed nodes representing the byte in LSB-first order.
fn const_to_feeds(builder: &CircuitBuilder, value: u8) -> [Node<Feed>; 8] {
    value
        .iter_lsb0()
        .map(|bit| {
            if bit {
                builder.get_const_one()
            } else {
                builder.get_const_zero()
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("u8 always has 8 bits")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{eq, gt, gte, lt, lte, ne};
    use mpz_circuits::evaluate;

    #[test]
    fn test_compile_and() {
        // data[0] < data[1] AND data[2] == 2
        let pred = Pred::and(vec![lt(0, 1usize), eq(2, 2u8)]);

        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [1u8, 2, 2]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [1u8, 2, 3]).unwrap();
        assert_eq!(res, false); // second fails
        let res: bool = evaluate!(circ, [5u8, 2, 2]).unwrap();
        assert_eq!(res, false); // first fails
    }

    #[test]
    fn test_compile_or() {
        // data[0] < data[1] OR data[2] == 2
        let pred = Pred::or(vec![lt(0, 1usize), eq(2, 2u8)]);

        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [1u8, 2, 0]).unwrap();
        assert_eq!(res, true); // first true
        let res: bool = evaluate!(circ, [5u8, 2, 2]).unwrap();
        assert_eq!(res, true); // second true
        let res: bool = evaluate!(circ, [5u8, 2, 0]).unwrap();
        assert_eq!(res, false); // both false
    }

    #[test]
    fn test_compile_not() {
        // NOT (data[0] < data[1])
        let pred = Pred::not(lt(0, 1usize));

        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [5u8, 3]).unwrap();
        assert_eq!(res, true); // 5 < 3 is false
        let res: bool = evaluate!(circ, [1u8, 3]).unwrap();
        assert_eq!(res, false); // 1 < 3 is true
    }

    #[test]
    fn test_compile_const_rhs() {
        // data[0] < 22
        let pred = lt(0, 22u8);

        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, 5u8).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, 23u8).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_index_rhs() {
        // data[0] < data[1]
        let pred = lt(0, 1usize);

        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, 5u8, 10u8).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, 23u8, 5u8).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_same_index() {
        // data[0] == data[0] (always true)
        let pred1 = eq(0, 0usize);
        // data[0] < data[0] (always false)
        let pred2 = lt(0, 0usize);

        let res: bool = evaluate!(Compiler::new().compile(&pred1), 5u8).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(Compiler::new().compile(&pred2), 5u8).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_eq() {
        let pred = eq(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [5u8, 5]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [1u8, 3]).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_ne() {
        let pred = ne(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [5u8, 6]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [1u8, 1]).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_gt() {
        let pred = gt(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [7u8, 6]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [1u8, 1]).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_gte() {
        let pred = gte(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [7u8, 7]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [0u8, 1]).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_lt() {
        let pred = lt(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [2u8, 7]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [4u8, 1]).unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_compile_lte() {
        let pred = lte(0, 1usize);
        let circ = Compiler::new().compile(&pred);

        let res: bool = evaluate!(circ, [2u8, 2]).unwrap();
        assert_eq!(res, true);
        let res: bool = evaluate!(circ, [4u8, 1]).unwrap();
        assert_eq!(res, false);
    }
}
