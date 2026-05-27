//! Slot-kind algebra. Pure functions over [`SlotKind`] tags that capture
//! the QuickSilver polynomial-lift rules:
//!
//! * `Zero × _ = Zero`
//! * `Subfield × Subfield = Subfield` (stays in `W`)
//! * `Subfield × Extension = Extension` (via `scale_by_subfield`)
//! * `Extension × Extension = Extension` (full mul — the one we can't avoid)
//! * `Zero + x = x`, `Subfield + Subfield = Subfield`, anything-mixed =
//!   Extension
//!
//! Used by the tracing layer to populate each node's `slot_kinds`; the
//! evaluator and emitter apply the same rules to produce values or source.

use crate::ir::SlotKind;

/// `Add(a, b)` slot kinds. `da` / `db` are operand degrees so we can
/// compute the Δ-shifts; slice lengths are `da+1` / `db+1`.
pub(crate) fn add_slot_kinds(
    a_kinds: &[SlotKind],
    da: usize,
    b_kinds: &[SlotKind],
    db: usize,
) -> Vec<SlotKind> {
    let d = da.max(db);
    let shift_a = d - da;
    let shift_b = d - db;
    (0..=d)
        .map(|k| {
            let from_a = if k >= shift_a {
                Some(a_kinds[k - shift_a])
            } else {
                None
            };
            let from_b = if k >= shift_b {
                Some(b_kinds[k - shift_b])
            } else {
                None
            };
            combine_add_kind(from_a, from_b)
        })
        .collect()
}

pub(crate) fn combine_add_kind(a: Option<SlotKind>, b: Option<SlotKind>) -> SlotKind {
    use SlotKind::*;
    match (a, b) {
        (None | Some(Zero), None | Some(Zero)) => Zero,
        (None | Some(Zero), Some(x)) | (Some(x), None | Some(Zero)) => x,
        (Some(Subfield), Some(Subfield)) => Subfield,
        _ => Extension, // any Extension in the mix → Extension
    }
}

/// `Mul(a, b)` slot kinds — convolution.
pub(crate) fn mul_slot_kinds(a_kinds: &[SlotKind], b_kinds: &[SlotKind]) -> Vec<SlotKind> {
    let da = a_kinds.len() - 1;
    let db = b_kinds.len() - 1;
    let d = da + db;
    let mut out = vec![SlotKind::Zero; d + 1];
    for i in 0..=da {
        for j in 0..=db {
            let term = mul_pair_kind(a_kinds[i], b_kinds[j]);
            out[i + j] = combine_add_kind(Some(out[i + j]), Some(term));
        }
    }
    out
}

pub(crate) fn mul_pair_kind(a: SlotKind, b: SlotKind) -> SlotKind {
    use SlotKind::*;
    match (a, b) {
        (Zero, _) | (_, Zero) => Zero,
        (Subfield, Subfield) => Subfield,
        // mixed → Extension via scale_by_subfield;
        // both Ext → Extension via full mul.
        _ => Extension,
    }
}
