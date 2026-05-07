//! Shared Schwartz-Zippel soundness-budget arithmetic.

/// Largest cumulative batch size `T` compatible with the given statistical
/// security parameter (SSP).
///
/// The Schwartz-Zippel bound on the overall cheating probability is
/// `(T + d_max) / 2^field_bits`. Requiring this to be at most `2^-ssp` yields
/// `T ≤ 2^(field_bits − ssp) − d_max`.
///
/// Special cases:
/// - `ssp ≥ field_bits` → no `T` satisfies the bound (`0`).
/// - headroom `≥ 64` → clamp at `u64::MAX`.
///
/// Callers must pass `ssp ≥ 1`; the public constructors enforce a stricter
/// minimum of [`crate::DEFAULT_SSP`].
pub(crate) fn max_evaluations(field_bits: usize, ssp: u32, d_max: usize) -> u64 {
    let sec = ssp as usize;
    if sec >= field_bits {
        return 0;
    }
    let headroom = field_bits - sec;
    let total = if headroom >= 64 {
        u64::MAX
    } else {
        1u64 << headroom
    };
    total.saturating_sub(d_max as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf64_with_40_bits() {
        // 2^(64-40) - 2 = 2^24 - 2
        assert_eq!(max_evaluations(64, 40, 2), (1u64 << 24) - 2);
    }

    #[test]
    fn unreachable_when_security_ge_field() {
        assert_eq!(max_evaluations(64, 64, 2), 0);
        assert_eq!(max_evaluations(64, 80, 2), 0);
    }

    #[test]
    fn headroom_saturates_at_u64_max() {
        // 128-bit field, 40-bit security → headroom 88, exceeds u64.
        assert_eq!(max_evaluations(128, 40, 2), u64::MAX - 2);
    }
}
