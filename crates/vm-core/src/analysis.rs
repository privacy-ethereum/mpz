//! Side-effect analysis over an [`mpz_vm_ir`] [`FunctionBody`].
//!
//! The IR's control-flow terminators carry only the structural shape of a
//! branch (condition, targets, and join block). The MPC interpreter needs
//! additional, consumer-specific information about *what a branch's region
//! does*: which registers, globals, and memory it may write, and whether the
//! branch enters genuine private control flow or is publicly deducible.
//!
//! That information is derived purely from the [`FunctionBody`], so it is
//! computed here as a cached side analysis rather than baked into the IR.

use std::collections::{HashMap, HashSet, VecDeque};

use mpz_vm_ir::{BasicBlock, BlockId, FunctionBody, Instruction, Reg, Terminator};

/// Side-effect info for all blocks reachable from a branch up to its join.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BranchRegion {
    /// Whether any block in the region performs a memory store.
    pub has_memory_store: bool,
    /// Whether any block in the region performs a call.
    pub has_call: bool,
    /// The globals written anywhere in the region, sorted and deduplicated.
    pub globals_written: Vec<u32>,
    /// The registers written anywhere in the region, sorted and deduplicated.
    pub registers_written: Vec<Reg>,
    /// Whether the join block is path-independent (all non-trivial paths
    /// reach it). When false, the delegate must run until function return.
    pub join_is_path_independent: bool,
    /// All non-trivial paths diverge (Return/Unreachable). The branch
    /// outcome is publicly deducible — not private CF.
    pub bail_out: bool,
}

/// Cached per-function branch analysis.
///
/// Maps the index of each branch block (one ending in `BrCond`/`BrTable`) to
/// its computed [`BranchRegion`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FunctionAnalysis {
    regions: HashMap<usize, BranchRegion>,
}

impl FunctionAnalysis {
    /// Computes the branch analysis for every `BrCond`/`BrTable` in `body`.
    pub(crate) fn compute(body: &FunctionBody) -> Self {
        let branch_blocks: Vec<(usize, BlockId)> = body
            .blocks
            .iter()
            .enumerate()
            .filter_map(|(i, block)| match &block.terminator {
                Terminator::BrCond { join, .. } | Terminator::BrTable { join, .. } => {
                    Some((i, *join))
                }
                _ => None,
            })
            .collect();

        let mut regions = HashMap::new();
        for (block_idx, join) in branch_blocks {
            let starts = terminator_successors(&body.blocks[block_idx].terminator);
            let region = analyze_region(&body.blocks, &starts, join);
            regions.insert(block_idx, region);
        }

        Self { regions }
    }

    /// Returns the [`BranchRegion`] for the branch block at `block`.
    pub(crate) fn region(&self, block: BlockId) -> &BranchRegion {
        self.regions
            .get(&block.index())
            .expect("branch block should have a computed region")
    }
}

/// Walk all blocks reachable from `starts` up to (but not including) `join`,
/// collecting side-effect information.
fn analyze_region(blocks: &[BasicBlock], starts: &[BlockId], join: BlockId) -> BranchRegion {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut has_memory_store = false;
    let mut has_call = false;
    let mut globals_written = HashSet::new();
    let mut registers_written = HashSet::new();
    let mut any_nontrivial_reaches_join = false;
    let mut has_nontrivial_start = false;

    for &start in starts {
        if start != join && visited.insert(start) {
            queue.push_back(start);
            has_nontrivial_start = true;
        }
    }

    while let Some(block_id) = queue.pop_front() {
        let block = match blocks.get(block_id.index()) {
            Some(b) => b,
            None => continue,
        };

        scan_block_side_effects(
            block,
            &mut has_memory_store,
            &mut has_call,
            &mut globals_written,
            &mut registers_written,
        );

        for succ in terminator_successors(&block.terminator) {
            if succ == join {
                any_nontrivial_reaches_join = true;
            } else if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    let mut globals_vec: Vec<u32> = globals_written.into_iter().collect();
    globals_vec.sort_unstable();

    let mut regs_vec: Vec<Reg> = registers_written.into_iter().collect();
    regs_vec.sort_unstable();

    BranchRegion {
        has_memory_store,
        has_call,
        globals_written: globals_vec,
        registers_written: regs_vec,
        join_is_path_independent: any_nontrivial_reaches_join,
        bail_out: has_nontrivial_start
            && (!any_nontrivial_reaches_join
                || matches!(
                    blocks.get(join.index()).map(|b| &b.terminator),
                    Some(Terminator::Unreachable) | Some(Terminator::Return { .. })
                )),
    }
}

fn scan_block_side_effects(
    block: &BasicBlock,
    has_memory_store: &mut bool,
    has_call: &mut bool,
    globals_written: &mut HashSet<u32>,
    registers_written: &mut HashSet<Reg>,
) {
    for instr in &block.body {
        if let Some(dst) = instr.dst() {
            registers_written.insert(dst);
        }
        match instr {
            Instruction::GlobalSet { global_idx, .. } => {
                globals_written.insert(*global_idx);
            }
            Instruction::Store { .. }
            | Instruction::MemoryFill { .. }
            | Instruction::MemoryCopy { .. }
            | Instruction::MemoryInit { .. } => {
                *has_memory_store = true;
            }
            Instruction::Call { .. } | Instruction::CallIndirect { .. } => {
                *has_call = true;
            }
            _ => {}
        }
    }
}

fn terminator_successors(terminator: &Terminator) -> Vec<BlockId> {
    match terminator {
        Terminator::Jump { target } => vec![*target],
        Terminator::BrCond {
            then_target,
            else_target,
            ..
        } => vec![*then_target, *else_target],
        Terminator::BrTable {
            targets, default, ..
        } => {
            let mut s = targets.clone();
            s.push(*default);
            s
        }
        Terminator::Return { .. } | Terminator::Unreachable => vec![],
    }
}
