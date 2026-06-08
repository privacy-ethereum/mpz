use crate::{BlockId, Reg, Result, ValidationError};

/// Tracks a control flow scope (block/loop/if) for CFG construction.
#[derive(Clone)]
pub(super) struct Scope {
    /// Stack height when entering this scope.
    pub stack_height: usize,
    /// Whether we were unreachable when entering.
    pub was_unreachable: bool,
    /// Result arity of this block.
    pub result_arity: usize,
    /// Whether this is a loop.
    pub is_loop: bool,
    /// Whether this is an if block.
    pub is_if: bool,
    /// Pre-allocated result register for blocks with results.
    pub block_result_reg: Option<Reg>,
    /// Whether the then branch was reachable (set at Else).
    pub then_was_reachable: bool,
    /// Continuation block (code after End). For loops, also used at End.
    pub continuation: BlockId,
    /// For if: the else block (or join if no else).
    pub else_block: Option<BlockId>,
}

/// Get the branch target BlockId for a given depth from the scope stack.
/// Returns `Ok(None)` if depth targets the function level (equivalent to
/// return).
pub(super) fn get_br_target(scopes: &[Scope], depth: u32) -> Result<Option<BlockId>> {
    let depth_usize = depth as usize;
    if depth_usize >= scopes.len() {
        Ok(None)
    } else {
        let idx = scopes.len() - 1 - depth_usize;
        let scope = &scopes[idx];
        if scope.is_loop {
            let header = scope
                .else_block
                .ok_or(ValidationError::MissingScope("loop scope without header"))?;
            Ok(Some(header))
        } else {
            Ok(Some(scope.continuation))
        }
    }
}

/// Get the join (immediate post-dominator) BlockId for a branch at the given
/// depth. Returns `None` if depth targets the function level (conditional
/// return), in which case the caller should use the fall-through block.
pub(super) fn get_br_join(scopes: &[Scope], depth: u32) -> Option<BlockId> {
    let idx = scopes.len().checked_sub(1 + depth as usize)?;
    Some(scopes[idx].continuation)
}
