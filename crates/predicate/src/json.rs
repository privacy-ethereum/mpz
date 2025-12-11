//! Pre-built predicates for validating JSON objects.

use crate::{eq, gte, lte, Pred};
use rangeset::prelude::RangeSet;

/// Builds a predicate that validates a non-empty JSON integer (digits only).
pub fn validate_integer(range: RangeSet<usize>) -> Pred {
    let preds = range
        .iter_values()
        .map(|idx| Pred::and(vec![lte(idx, 57u8), gte(idx, 48u8)]))
        .collect::<Vec<_>>();
    Pred::and(preds)
}

/// Builds a predicate that validates a JSON number.
///
/// JSON number grammar:
/// ```text
/// number = [ "-" ] int [ frac ] [ exp ]
/// int    = "0" | ( digit1-9 *digit )
/// frac   = "." 1*digit
/// exp    = ( "e" | "E" ) [ "+" | "-" ] 1*digit
/// ```
pub fn validate_number(range: RangeSet<usize>) -> Pred {
    let len = range.len();
    assert!(len > 0);

    let positions: Vec<usize> = range.iter_values().collect();

    // Character class predicates for each position
    let is_minus: Vec<Pred> = positions.iter().map(|&p| eq(p, b'-')).collect();
    let is_zero: Vec<Pred> = positions.iter().map(|&p| eq(p, b'0')).collect();
    let is_digit: Vec<Pred> = positions
        .iter()
        .map(|&p| Pred::and(vec![gte(p, b'0'), lte(p, b'9')]))
        .collect();
    let is_digit_1_9: Vec<Pred> = positions
        .iter()
        .map(|&p| Pred::and(vec![gte(p, b'1'), lte(p, b'9')]))
        .collect();
    let is_dot: Vec<Pred> = positions.iter().map(|&p| eq(p, b'.')).collect();
    let is_exp: Vec<Pred> = positions
        .iter()
        .map(|&p| Pred::or(vec![eq(p, b'e'), eq(p, b'E')]))
        .collect();
    let is_sign: Vec<Pred> = positions
        .iter()
        .map(|&p| Pred::or(vec![eq(p, b'+'), eq(p, b'-')]))
        .collect();

    // State tracking: after processing position i, which states are possible?
    // States represent where we are in the grammar:
    // - in_int_zero: integer part is exactly "0" (or "-0")
    // - in_int_digits: in integer digits (after 1-9)
    // - in_frac_start: just saw '.', need at least one digit
    // - in_frac_digits: in fractional digits
    // - in_exp_start: just saw 'e'/'E', need sign or digit
    // - in_exp_sign: just saw exp sign, need at least one digit
    // - in_exp_digits: in exponent digits

    let mut in_int_zero: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_int_digits: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_frac_start: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_frac_digits: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_exp_start: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_exp_sign: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut in_exp_digits: Vec<Option<Pred>> = Vec::with_capacity(len);

    let mut is_valid: Vec<Pred> = Vec::with_capacity(len);

    for i in 0..len {
        if i == 0 {
            // First character: '-', '0', or '1'-'9'
            in_int_zero.push(Some(is_zero[i].clone()));
            in_int_digits.push(Some(is_digit_1_9[i].clone()));
            in_frac_start.push(None);
            in_frac_digits.push(None);
            in_exp_start.push(None);
            in_exp_sign.push(None);
            in_exp_digits.push(None);

            let valid = Pred::or(vec![
                is_minus[i].clone(),
                is_zero[i].clone(),
                is_digit_1_9[i].clone(),
            ]);
            is_valid.push(valid);
        } else if i == 1 {
            // Second character depends on first
            let prev_was_minus = is_minus[0].clone();
            let prev_was_zero = is_zero[0].clone();
            let prev_was_digit_1_9 = is_digit_1_9[0].clone();

            // Transitions to int_zero: '-' followed by '0'
            let after_minus_zero = Pred::and(vec![prev_was_minus.clone(), is_zero[i].clone()]);
            in_int_zero.push(Some(after_minus_zero));

            // Transitions to int_digits: '-' + 1-9, or 1-9 + digit
            let after_minus_digit =
                Pred::and(vec![prev_was_minus.clone(), is_digit_1_9[i].clone()]);
            let continue_int = Pred::and(vec![prev_was_digit_1_9.clone(), is_digit[i].clone()]);
            in_int_digits.push(Some(Pred::or(vec![after_minus_digit, continue_int])));

            // Transitions to frac_start: '0' + '.', or 1-9 + '.'
            let zero_to_frac = Pred::and(vec![prev_was_zero.clone(), is_dot[i].clone()]);
            let digit_to_frac = Pred::and(vec![prev_was_digit_1_9.clone(), is_dot[i].clone()]);
            in_frac_start.push(Some(Pred::or(vec![zero_to_frac, digit_to_frac])));

            in_frac_digits.push(None);

            // Transitions to exp_start: '0' + e/E, or 1-9 + e/E
            let zero_to_exp = Pred::and(vec![prev_was_zero.clone(), is_exp[i].clone()]);
            let digit_to_exp = Pred::and(vec![prev_was_digit_1_9.clone(), is_exp[i].clone()]);
            in_exp_start.push(Some(Pred::or(vec![zero_to_exp, digit_to_exp])));

            in_exp_sign.push(None);
            in_exp_digits.push(None);

            let valid = Pred::or(vec![
                Pred::and(vec![prev_was_minus.clone(), is_zero[i].clone()]),
                Pred::and(vec![prev_was_minus.clone(), is_digit_1_9[i].clone()]),
                Pred::and(vec![prev_was_zero.clone(), is_dot[i].clone()]),
                Pred::and(vec![prev_was_zero.clone(), is_exp[i].clone()]),
                Pred::and(vec![prev_was_digit_1_9.clone(), is_digit[i].clone()]),
                Pred::and(vec![prev_was_digit_1_9.clone(), is_dot[i].clone()]),
                Pred::and(vec![prev_was_digit_1_9.clone(), is_exp[i].clone()]),
            ]);
            is_valid.push(valid);
        } else {
            // General case: i >= 2
            let new_int_zero: Vec<Pred> = Vec::new();
            let mut new_int_digits: Vec<Pred> = Vec::new();
            let mut new_frac_start: Vec<Pred> = Vec::new();
            let mut new_frac_digits: Vec<Pred> = Vec::new();
            let mut new_exp_start: Vec<Pred> = Vec::new();
            let mut new_exp_sign: Vec<Pred> = Vec::new();
            let mut new_exp_digits: Vec<Pred> = Vec::new();
            let mut valid_preds: Vec<Pred> = Vec::new();

            // From int_zero: -> frac_start ('.') or exp_start ('e'/'E')
            if let Some(ref prev) = in_int_zero[i - 1] {
                let to_frac = Pred::and(vec![prev.clone(), is_dot[i].clone()]);
                let to_exp = Pred::and(vec![prev.clone(), is_exp[i].clone()]);
                new_frac_start.push(to_frac.clone());
                new_exp_start.push(to_exp.clone());
                valid_preds.push(to_frac);
                valid_preds.push(to_exp);
            }

            // From int_digits: -> digit (stay), frac_start ('.'), or exp_start ('e'/'E')
            if let Some(ref prev) = in_int_digits[i - 1] {
                let stay = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                let to_frac = Pred::and(vec![prev.clone(), is_dot[i].clone()]);
                let to_exp = Pred::and(vec![prev.clone(), is_exp[i].clone()]);
                new_int_digits.push(stay.clone());
                new_frac_start.push(to_frac.clone());
                new_exp_start.push(to_exp.clone());
                valid_preds.push(stay);
                valid_preds.push(to_frac);
                valid_preds.push(to_exp);
            }

            // From frac_start: -> frac_digits (digit required)
            if let Some(ref prev) = in_frac_start[i - 1] {
                let to_digits = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                new_frac_digits.push(to_digits.clone());
                valid_preds.push(to_digits);
            }

            // From frac_digits: -> digit (stay) or exp_start ('e'/'E')
            if let Some(ref prev) = in_frac_digits[i - 1] {
                let stay = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                let to_exp = Pred::and(vec![prev.clone(), is_exp[i].clone()]);
                new_frac_digits.push(stay.clone());
                new_exp_start.push(to_exp.clone());
                valid_preds.push(stay);
                valid_preds.push(to_exp);
            }

            // From exp_start: -> exp_sign ('+'/'-') or exp_digits (digit)
            if let Some(ref prev) = in_exp_start[i - 1] {
                let to_sign = Pred::and(vec![prev.clone(), is_sign[i].clone()]);
                let to_digits = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                new_exp_sign.push(to_sign.clone());
                new_exp_digits.push(to_digits.clone());
                valid_preds.push(to_sign);
                valid_preds.push(to_digits);
            }

            // From exp_sign: -> exp_digits (digit required)
            if let Some(ref prev) = in_exp_sign[i - 1] {
                let to_digits = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                new_exp_digits.push(to_digits.clone());
                valid_preds.push(to_digits);
            }

            // From exp_digits: -> digit (stay)
            if let Some(ref prev) = in_exp_digits[i - 1] {
                let stay = Pred::and(vec![prev.clone(), is_digit[i].clone()]);
                new_exp_digits.push(stay.clone());
                valid_preds.push(stay);
            }

            in_int_zero.push(if new_int_zero.is_empty() {
                None
            } else {
                Some(Pred::or(new_int_zero))
            });
            in_int_digits.push(if new_int_digits.is_empty() {
                None
            } else {
                Some(Pred::or(new_int_digits))
            });
            in_frac_start.push(if new_frac_start.is_empty() {
                None
            } else {
                Some(Pred::or(new_frac_start))
            });
            in_frac_digits.push(if new_frac_digits.is_empty() {
                None
            } else {
                Some(Pred::or(new_frac_digits))
            });
            in_exp_start.push(if new_exp_start.is_empty() {
                None
            } else {
                Some(Pred::or(new_exp_start))
            });
            in_exp_sign.push(if new_exp_sign.is_empty() {
                None
            } else {
                Some(Pred::or(new_exp_sign))
            });
            in_exp_digits.push(if new_exp_digits.is_empty() {
                None
            } else {
                Some(Pred::or(new_exp_digits))
            });

            assert!(
                !valid_preds.is_empty(),
                "No valid transitions at position {i}"
            );
            is_valid.push(Pred::or(valid_preds));
        }
    }

    // Final validation: must end in a terminal state
    // Terminal: int_zero, int_digits, frac_digits, exp_digits
    // Non-terminal: frac_start, exp_start, exp_sign (all require more input)
    let last = len - 1;
    let mut terminal_states: Vec<Pred> = Vec::new();

    if len == 1 {
        // Single character: must be a digit
        terminal_states.push(is_digit[0].clone());
    } else {
        if let Some(ref state) = in_int_zero[last] {
            terminal_states.push(state.clone());
        }
        if let Some(ref state) = in_int_digits[last] {
            terminal_states.push(state.clone());
        }
        if let Some(ref state) = in_frac_digits[last] {
            terminal_states.push(state.clone());
        }
        if let Some(ref state) = in_exp_digits[last] {
            terminal_states.push(state.clone());
        }
    }

    assert!(
        !terminal_states.is_empty(),
        "No terminal states possible for length {len}"
    );

    is_valid.push(Pred::or(terminal_states));
    Pred::and(is_valid)
}

/// Builds a predicate that validates a non-empty JSON string (content between
/// quotes).
pub fn validate_string(range: RangeSet<usize>) -> Pred {
    let len = range.len();
    assert!(len > 0);

    let positions: Vec<usize> = range.iter_values().collect();
    let mut data: Vec<ByteData> = positions.iter().map(|&pos| ByteData::new(pos)).collect();

    // Track escape sequences - Option<Pred> where None means "can't start here"
    let mut is_escape_start: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut is_unicode_escape_start: Vec<Option<Pred>> = Vec::with_capacity(len);

    // Track UTF-8 multi-byte sequences
    let mut starts_utf8_2: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut starts_utf8_3: Vec<Option<Pred>> = Vec::with_capacity(len);
    let mut starts_utf8_4: Vec<Option<Pred>> = Vec::with_capacity(len);

    let mut is_valid = Vec::with_capacity(len);

    for i in 0..len {
        // Compute if this position is consumed by a previous escape or UTF-8 sequence
        let mut consumed_by: Vec<Option<Pred>> = Vec::new();

        // Consumed by simple escape at i-1 (not unicode)
        if i >= 1 {
            if let Some(prev_starts) = &is_escape_start[i - 1] {
                let prev_is_simple = match &is_unicode_escape_start[i - 1] {
                    Some(prev_is_unicode) => {
                        // prev_starts AND NOT prev_is_unicode
                        Pred::and(vec![
                            prev_starts.clone(),
                            Pred::not(prev_is_unicode.clone()),
                        ])
                    }
                    None => {
                        // No unicode escape possible, so if escape starts, it's simple
                        prev_starts.clone()
                    }
                };
                consumed_by.push(Some(prev_is_simple));
            }
        }

        // Consumed by unicode escape at i-1 through i-5
        for offset in 1..=5 {
            if i >= offset {
                consumed_by.push(is_unicode_escape_start[i - offset].clone());
            }
        }

        // Consumed by UTF-8 2-byte sequence starting at i-1
        if i >= 1 {
            consumed_by.push(starts_utf8_2[i - 1].clone());
        }

        // Consumed by UTF-8 3-byte sequence starting at i-1 or i-2
        for offset in 1..=2 {
            if i >= offset {
                consumed_by.push(starts_utf8_3[i - offset].clone());
            }
        }

        // Consumed by UTF-8 4-byte sequence starting at i-1, i-2, or i-3
        for offset in 1..=3 {
            if i >= offset {
                consumed_by.push(starts_utf8_4[i - offset].clone());
            }
        }

        let pos_consumed = or_opts(consumed_by);

        // Compute escape sequence starts (only if not consumed)
        let is_escape = data[i].is_escape();

        let (could_start_escape, could_start_unicode): (Option<Pred>, Option<Pred>) = if len - i > 1
        {
            let next_is_simple_suffix = data[i + 1].is_escape_suffix();
            let next_is_unicode = data[i + 1].is_unicode_escape_suffix();

            let is_valid_unicode: Option<Pred> = if len - i > 5 {
                let is_hex_0 = data[i + 2].is_hex();
                let is_hex_1 = data[i + 3].is_hex();
                let is_hex_2 = data[i + 4].is_hex();
                let is_hex_3 = data[i + 5].is_hex();
                Some(Pred::and(vec![
                    next_is_unicode.clone(),
                    is_hex_0,
                    is_hex_1,
                    is_hex_2,
                    is_hex_3,
                ]))
            } else {
                None
            };

            // Valid escape = simple suffix OR valid unicode
            let is_valid_escape_seq = match &is_valid_unicode {
                Some(unicode) => Pred::or(vec![next_is_simple_suffix, unicode.clone()]),
                None => next_is_simple_suffix,
            };

            let could_start = Pred::and(vec![is_escape.clone(), is_valid_escape_seq]);
            let could_unicode = is_valid_unicode.map(|u| Pred::and(vec![is_escape.clone(), u]));

            (Some(could_start), could_unicode)
        } else {
            (None, None)
        };

        // Apply "not consumed" constraint
        let starts_escape = match (&could_start_escape, &pos_consumed) {
            (Some(escape), Some(consumed)) => {
                Some(Pred::and(vec![escape.clone(), Pred::not(consumed.clone())]))
            }
            (Some(escape), None) => Some(escape.clone()),
            (None, _) => None,
        };

        let starts_unicode = match (&could_start_unicode, &pos_consumed) {
            (Some(unicode), Some(consumed)) => Some(Pred::and(vec![
                unicode.clone(),
                Pred::not(consumed.clone()),
            ])),
            (Some(unicode), None) => Some(unicode.clone()),
            (None, _) => None,
        };

        is_escape_start.push(starts_escape.clone());
        is_unicode_escape_start.push(starts_unicode.clone());

        // Compute UTF-8 sequence starts (only if not consumed)
        // 2-byte: 0xC2-0xDF followed by 0x80-0xBF
        let could_start_utf8_2: Option<Pred> = if len - i > 1 {
            let is_2byte_start = data[i].is_2byte_start();
            let next_is_cont = data[i + 1].is_continuation();
            Some(Pred::and(vec![is_2byte_start, next_is_cont]))
        } else {
            None
        };

        // 3-byte: 0xE0-0xEF with special cases
        let could_start_utf8_3: Option<Pred> = if len - i > 2 {
            let is_3byte_start = data[i].is_3byte_start();
            let cont1 = data[i + 1].is_continuation();
            let cont2 = data[i + 2].is_continuation();

            let is_e0 = data[i].is_e0();
            let is_ed = data[i].is_ed();
            let not_e0 = Pred::not(is_e0.clone());
            let not_ed = Pred::not(is_ed.clone());
            let is_normal_3byte = Pred::and(vec![is_3byte_start, not_e0, not_ed]);

            // E0: second byte must be A0-BF
            let cont1_a0_bf = data[i + 1].is_cont_a0_bf();
            let e0_valid = Pred::and(vec![is_e0, cont1_a0_bf]);

            // ED: second byte must be 80-9F
            let cont1_80_9f = data[i + 1].is_cont_80_9f();
            let ed_valid = Pred::and(vec![is_ed, cont1_80_9f]);

            // Normal 3-byte: second byte 80-BF
            let normal_valid = Pred::and(vec![is_normal_3byte, cont1]);

            let first_two_valid = Pred::or(vec![e0_valid, ed_valid, normal_valid]);
            Some(Pred::and(vec![first_two_valid, cont2]))
        } else {
            None
        };

        // 4-byte: 0xF0-0xF4 with special cases
        let could_start_utf8_4: Option<Pred> = if len - i > 3 {
            let is_4byte_start = data[i].is_4byte_start();
            let cont1 = data[i + 1].is_continuation();
            let cont2 = data[i + 2].is_continuation();
            let cont3 = data[i + 3].is_continuation();

            let is_f0 = data[i].is_f0();
            let is_f4 = data[i].is_f4();
            let not_f0 = Pred::not(is_f0.clone());
            let not_f4 = Pred::not(is_f4.clone());
            let is_normal_4byte = Pred::and(vec![is_4byte_start, not_f0, not_f4]);

            // F0: second byte must be 90-BF
            let cont1_90_bf = data[i + 1].is_cont_90_bf();
            let f0_valid = Pred::and(vec![is_f0, cont1_90_bf]);

            // F4: second byte must be 80-8F
            let cont1_80_8f = data[i + 1].is_cont_80_8f();
            let f4_valid = Pred::and(vec![is_f4, cont1_80_8f]);

            // Normal 4-byte (F1-F3): second byte 80-BF
            let normal_valid = Pred::and(vec![is_normal_4byte, cont1]);

            let first_two_valid = Pred::or(vec![f0_valid, f4_valid, normal_valid]);
            let first_three_valid = Pred::and(vec![first_two_valid, cont2]);
            Some(Pred::and(vec![first_three_valid, cont3]))
        } else {
            None
        };

        // Apply "not consumed" constraint to UTF-8 starts
        let utf8_2_start = match (&could_start_utf8_2, &pos_consumed) {
            (Some(start), Some(consumed)) => {
                Some(Pred::and(vec![start.clone(), Pred::not(consumed.clone())]))
            }
            (Some(start), None) => Some(start.clone()),
            (None, _) => None,
        };

        let utf8_3_start = match (&could_start_utf8_3, &pos_consumed) {
            (Some(start), Some(consumed)) => {
                Some(Pred::and(vec![start.clone(), Pred::not(consumed.clone())]))
            }
            (Some(start), None) => Some(start.clone()),
            (None, _) => None,
        };

        let utf8_4_start = match (&could_start_utf8_4, &pos_consumed) {
            (Some(start), Some(consumed)) => {
                Some(Pred::and(vec![start.clone(), Pred::not(consumed.clone())]))
            }
            (Some(start), None) => Some(start.clone()),
            (None, _) => None,
        };

        starts_utf8_2.push(utf8_2_start.clone());
        starts_utf8_3.push(utf8_3_start.clone());
        starts_utf8_4.push(utf8_4_start.clone());

        // Validate this position
        let is_ctrl = data[i].is_ctrl();
        let is_not_ctrl = Pred::not(is_ctrl);
        let is_quote = data[i].is_quote();
        let is_not_quote = Pred::not(is_quote);
        let is_not_escape = Pred::not(is_escape);

        // Quote is valid if: not a quote, OR preceded by an escape start
        let quote_ok = if i >= 1 {
            match &is_escape_start[i - 1] {
                Some(preceded_by_escape) => {
                    Pred::or(vec![is_not_quote, preceded_by_escape.clone()])
                }
                None => is_not_quote,
            }
        } else {
            is_not_quote
        };

        // Escape is valid if it starts a valid escape sequence
        let escape_ok = match &starts_escape {
            Some(starts) => Pred::or(vec![is_not_escape, starts.clone()]),
            None => is_not_escape,
        };

        // UTF-8 validation
        let is_2byte_start_byte = data[i].is_2byte_start();
        let is_3byte_start_byte = data[i].is_3byte_start();
        let is_4byte_start_byte = data[i].is_4byte_start();
        let is_continuation_byte = data[i].is_continuation();

        // If it's a multi-byte start, it must start a valid sequence
        let is_any_multibyte_start = Pred::or(vec![
            is_2byte_start_byte,
            is_3byte_start_byte,
            is_4byte_start_byte,
        ]);

        let starts_valid_multibyte =
            or_opts([utf8_2_start, utf8_3_start, utf8_4_start].into_iter());

        // multibyte_ok: not a multibyte start, OR starts a valid sequence
        let not_multibyte_start = Pred::not(is_any_multibyte_start);
        let multibyte_ok = match starts_valid_multibyte {
            Some(valid) => Pred::or(vec![not_multibyte_start, valid]),
            None => not_multibyte_start,
        };

        // Continuation bytes are only valid if consumed by a previous sequence
        let not_continuation = Pred::not(is_continuation_byte);
        let continuation_ok = match &pos_consumed {
            Some(consumed) => Pred::or(vec![not_continuation, consumed.clone()]),
            None => not_continuation,
        };

        // Invalid bytes: 0xC0, 0xC1, 0xF5-0xFF
        let is_c0 = eq(positions[i], 0xC0u8);
        let is_c1 = eq(positions[i], 0xC1u8);
        let gte_f5 = gte(positions[i], 0xF5u8);
        let is_invalid_byte = Pred::or(vec![is_c0, is_c1, gte_f5]);
        let not_invalid_byte = Pred::not(is_invalid_byte);

        // Combine all UTF-8 checks
        let utf8_ok = Pred::and(vec![multibyte_ok, continuation_ok, not_invalid_byte]);

        // When not consumed: must pass ctrl, quote, escape, and UTF-8 checks
        let valid_when_not_consumed = Pred::and(vec![is_not_ctrl, quote_ok, escape_ok, utf8_ok]);

        // Position is valid if: consumed OR (not consumed AND passes all checks)
        let pos_valid = match pos_consumed {
            Some(consumed) => {
                let is_not_consumed = Pred::not(consumed.clone());
                let not_consumed_and_valid =
                    Pred::and(vec![is_not_consumed, valid_when_not_consumed]);
                Pred::or(vec![consumed, not_consumed_and_valid])
            }
            None => {
                // Position can't be consumed, so it must pass all checks
                valid_when_not_consumed
            }
        };

        is_valid.push(pos_valid);
    }

    Pred::and(is_valid)
}

struct ByteData {
    pos: usize,
    is_ctrl: Option<Pred>,
    is_quote: Option<Pred>,
    is_escape: Option<Pred>,
    is_unicode: Option<Pred>,
    is_valid_escape: Option<Pred>,
    is_hex: Option<Pred>,
    // UTF-8 byte classification
    is_continuation: Option<Pred>,
    is_2byte_start: Option<Pred>,
    is_3byte_start: Option<Pred>,
    is_4byte_start: Option<Pred>,
    // Special UTF-8 cases
    is_e0: Option<Pred>,
    is_ed: Option<Pred>,
    is_f0: Option<Pred>,
    is_f4: Option<Pred>,
    // Continuation byte sub-ranges
    is_cont_80_8f: Option<Pred>,
    is_cont_80_9f: Option<Pred>,
    is_cont_90_bf: Option<Pred>,
    is_cont_a0_bf: Option<Pred>,
}

impl ByteData {
    fn new(pos: usize) -> Self {
        Self {
            pos,
            is_ctrl: None,
            is_quote: None,
            is_escape: None,
            is_unicode: None,
            is_valid_escape: None,
            is_hex: None,
            is_continuation: None,
            is_2byte_start: None,
            is_3byte_start: None,
            is_4byte_start: None,
            is_e0: None,
            is_ed: None,
            is_f0: None,
            is_f4: None,
            is_cont_80_8f: None,
            is_cont_80_9f: None,
            is_cont_90_bf: None,
            is_cont_a0_bf: None,
        }
    }

    fn is_ctrl(&mut self) -> Pred {
        self.is_ctrl
            .get_or_insert_with(|| lte(self.pos, 0x1Fu8))
            .clone()
    }

    fn is_quote(&mut self) -> Pred {
        self.is_quote
            .get_or_insert_with(|| eq(self.pos, b'"'))
            .clone()
    }

    fn is_escape(&mut self) -> Pred {
        self.is_escape
            .get_or_insert_with(|| eq(self.pos, b'\\'))
            .clone()
    }

    fn is_unicode_escape_suffix(&mut self) -> Pred {
        self.is_unicode
            .get_or_insert_with(|| eq(self.pos, b'u'))
            .clone()
    }

    fn is_escape_suffix(&mut self) -> Pred {
        self.is_valid_escape
            .get_or_insert_with(|| {
                // Valid escape suffixes: " / \ b f n r t (unicode 'u' handled separately)
                let chars: Vec<u8> = vec![b'"', b'/', b'\\', b'b', b'f', b'n', b'r', b't'];
                let atoms: Vec<Pred> = chars.iter().map(|c| eq(self.pos, *c)).collect();
                Pred::or(atoms)
            })
            .clone()
    }

    fn is_hex(&mut self) -> Pred {
        self.is_hex
            .get_or_insert_with(|| {
                // 0-9, a-f, A-F
                let is_digit = Pred::and(vec![gte(self.pos, b'0'), lte(self.pos, b'9')]);
                let is_lower = Pred::and(vec![gte(self.pos, b'a'), lte(self.pos, b'f')]);
                let is_upper = Pred::and(vec![gte(self.pos, b'A'), lte(self.pos, b'F')]);
                Pred::or(vec![is_digit, is_lower, is_upper])
            })
            .clone()
    }

    // UTF-8 classification methods

    fn is_continuation(&mut self) -> Pred {
        self.is_continuation
            .get_or_insert_with(|| {
                // 0x80-0xBF (10xxxxxx)
                Pred::and(vec![gte(self.pos, 0x80u8), lte(self.pos, 0xBFu8)])
            })
            .clone()
    }

    fn is_2byte_start(&mut self) -> Pred {
        self.is_2byte_start
            .get_or_insert_with(|| {
                // 0xC2-0xDF (excludes 0xC0-0xC1 which are overlong)
                Pred::and(vec![gte(self.pos, 0xC2u8), lte(self.pos, 0xDFu8)])
            })
            .clone()
    }

    fn is_3byte_start(&mut self) -> Pred {
        self.is_3byte_start
            .get_or_insert_with(|| {
                // 0xE0-0xEF
                Pred::and(vec![gte(self.pos, 0xE0u8), lte(self.pos, 0xEFu8)])
            })
            .clone()
    }

    fn is_4byte_start(&mut self) -> Pred {
        self.is_4byte_start
            .get_or_insert_with(|| {
                // 0xF0-0xF4 (excludes 0xF5+ which encode > U+10FFFF)
                Pred::and(vec![gte(self.pos, 0xF0u8), lte(self.pos, 0xF4u8)])
            })
            .clone()
    }

    fn is_e0(&mut self) -> Pred {
        self.is_e0
            .get_or_insert_with(|| eq(self.pos, 0xE0u8))
            .clone()
    }

    fn is_ed(&mut self) -> Pred {
        self.is_ed
            .get_or_insert_with(|| eq(self.pos, 0xEDu8))
            .clone()
    }

    fn is_f0(&mut self) -> Pred {
        self.is_f0
            .get_or_insert_with(|| eq(self.pos, 0xF0u8))
            .clone()
    }

    fn is_f4(&mut self) -> Pred {
        self.is_f4
            .get_or_insert_with(|| eq(self.pos, 0xF4u8))
            .clone()
    }

    fn is_cont_80_8f(&mut self) -> Pred {
        self.is_cont_80_8f
            .get_or_insert_with(|| Pred::and(vec![gte(self.pos, 0x80u8), lte(self.pos, 0x8Fu8)]))
            .clone()
    }

    fn is_cont_80_9f(&mut self) -> Pred {
        self.is_cont_80_9f
            .get_or_insert_with(|| Pred::and(vec![gte(self.pos, 0x80u8), lte(self.pos, 0x9Fu8)]))
            .clone()
    }

    fn is_cont_90_bf(&mut self) -> Pred {
        self.is_cont_90_bf
            .get_or_insert_with(|| Pred::and(vec![gte(self.pos, 0x90u8), lte(self.pos, 0xBFu8)]))
            .clone()
    }

    fn is_cont_a0_bf(&mut self) -> Pred {
        self.is_cont_a0_bf
            .get_or_insert_with(|| Pred::and(vec![gte(self.pos, 0xA0u8), lte(self.pos, 0xBFu8)]))
            .clone()
    }
}

/// Helper to build OR from a collection of optional predicates.
/// Returns None if no predicates are present (represents "always false" /
/// impossible).
fn or_opts(preds: impl IntoIterator<Item = Option<Pred>>) -> Option<Pred> {
    let collected: Vec<Pred> = preds.into_iter().flatten().collect();
    if collected.is_empty() {
        None
    } else {
        Some(Pred::or(collected))
    }
}

/// Helper to build AND from a collection of optional predicates.
/// Returns None if any predicate is None (since AND with false = false).
/// Returns the conjunction if all are present.
fn and_opts(preds: impl IntoIterator<Item = Option<Pred>>) -> Option<Pred> {
    let collected: Vec<Pred> = preds.into_iter().collect::<Option<Vec<_>>>()?;
    if collected.is_empty() {
        // AND of nothing = true, but we represent "no constraint" as None
        // In practice this shouldn't happen in our usage
        None
    } else {
        Some(Pred::and(collected))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::Compiler;
    use mpz_circuits::evaluate;
    use serde_json::value::RawValue;
    use std::{fs, path::PathBuf};

    #[test]
    fn test_validate_string() {
        const LENGTH: usize = 1024;

        let pred = validate_string(RangeSet::from(0..LENGTH));

        println!("done building predicate");

        let circ = Compiler::new().compile(&pred);

        println!(
            "JSON string length: {:?}; circuit AND gate count {:?}",
            LENGTH,
            circ.and_count()
        );
    }

    #[test]
    fn test_validate_number_and_gates() {
        const LENGTH: usize = 20;

        let pred = validate_number(RangeSet::from(0..LENGTH));

        println!("done building predicate");

        let circ = Compiler::new().compile(&pred);

        println!(
            "JSON string length: {:?}; circuit AND gate count {:?}",
            LENGTH,
            circ.and_count()
        );
    }

    #[test]
    fn test_json_test_suite_pass() {
        let folder = PathBuf::from("tests/json_test_suite_pass");

        for entry in fs::read_dir(&folder).expect("Failed to read JSON directory") {
            let entry = entry.expect("Invalid dir entry");
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let data =
                fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read {:?}", path));

            let parsed: Vec<Box<RawValue>> = serde_json::from_str(&data).unwrap();
            let raw_element = parsed[0].get();
            let inner = &raw_element[1..raw_element.len() - 1];

            if inner.is_empty() {
                // Empty string is vacuously valid
                continue;
            }

            let pred = validate_string(RangeSet::from(0..inner.len()));
            let circ = Compiler::new().compile(&pred);

            let out: bool = evaluate!(circ, inner.as_bytes()).unwrap();
            assert_eq!(out, true, "Failed for {:?}", path);
        }
    }

    #[test]
    fn test_json_test_suite_fail() {
        let folder = PathBuf::from("tests/json_test_suite_fail");

        for entry in fs::read_dir(&folder).expect("Failed to read JSON directory") {
            let entry = entry.expect("Invalid dir entry");
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            let raw = match fs::read_to_string(&path) {
                Ok(raw) => {
                    let trimmed = raw.trim();
                    assert!(trimmed.starts_with('[') && trimmed.ends_with(']'));
                    let inside = &trimmed[1..trimmed.len() - 1].trim();
                    assert!(inside.starts_with('"') && inside.ends_with('"'));
                    let inner_raw = &inside[1..inside.len() - 1];
                    inner_raw.as_bytes().to_vec()
                }
                Err(_) => {
                    let bytes: Vec<u8> = fs::read(&path).expect("failed to read file");
                    bytes[2..bytes.len() - 2].to_vec()
                }
            };

            if raw.is_empty() {
                continue;
            }

            let pred = validate_string(RangeSet::from(0..raw.len()));
            let circ = Compiler::new().compile(&pred);

            let out: bool = evaluate!(circ, raw).unwrap();
            assert_eq!(out, false, "Failed for {:?}", path);
        }
    }

    #[test]
    fn test_invalid_utf8() {
        let invalid_cases: Vec<(&str, Vec<u8>)> = vec![
            // Lone continuation bytes
            ("lone continuation byte 0x80", vec![0x80]),
            ("lone continuation byte 0xBF", vec![0xBF]),
            ("lone continuation byte in middle", vec![b'a', 0x80, b'b']),
            // Overlong encodings
            ("overlong 0xC0 0x80", vec![0xC0, 0x80]),
            ("overlong 0xC1 0xBF", vec![0xC1, 0xBF]),
            // Incomplete sequences
            ("incomplete 2-byte at end", vec![0xC2]),
            ("incomplete 2-byte followed by ASCII", vec![0xC2, b'a']),
            ("incomplete 3-byte missing 2 bytes", vec![0xE0]),
            ("incomplete 3-byte missing 1 byte", vec![0xE0, 0xA0]),
            ("incomplete 4-byte missing 3 bytes", vec![0xF0]),
            ("incomplete 4-byte missing 2 bytes", vec![0xF0, 0x90]),
            ("incomplete 4-byte missing 1 byte", vec![0xF0, 0x90, 0x80]),
            // E0 overlong
            ("E0 overlong second byte 0x80", vec![0xE0, 0x80, 0x80]),
            ("E0 overlong second byte 0x9F", vec![0xE0, 0x9F, 0x80]),
            // ED surrogate
            ("ED surrogate second byte 0xA0", vec![0xED, 0xA0, 0x80]),
            ("ED surrogate second byte 0xBF", vec![0xED, 0xBF, 0x80]),
            // F0 overlong
            ("F0 overlong second byte 0x80", vec![0xF0, 0x80, 0x80, 0x80]),
            ("F0 overlong second byte 0x8F", vec![0xF0, 0x8F, 0x80, 0x80]),
            // F4 out of range
            (
                "F4 out of range second byte 0x90",
                vec![0xF4, 0x90, 0x80, 0x80],
            ),
            (
                "F4 out of range second byte 0xBF",
                vec![0xF4, 0xBF, 0x80, 0x80],
            ),
            // Invalid start bytes
            ("invalid start byte 0xF5", vec![0xF5, 0x80, 0x80, 0x80]),
            ("invalid start byte 0xFF", vec![0xFF]),
            // Mixed
            (
                "valid then invalid continuation",
                vec![b'h', b'e', b'l', b'l', b'o', 0x80],
            ),
            (
                "valid 2-byte then lone continuation",
                vec![0xC2, 0x80, 0x80],
            ),
        ];

        for (name, bytes) in invalid_cases {
            if bytes.is_empty() {
                continue;
            }

            let pred = validate_string(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, &bytes).unwrap();

            assert_eq!(
                out, false,
                "Expected invalid UTF-8 for case '{}': {:02X?}",
                name, bytes
            );
        }
    }

    #[test]
    fn test_valid_utf8() {
        let valid_cases: Vec<(&str, Vec<u8>)> = vec![
            // ASCII
            ("simple ASCII", b"hello world".to_vec()),
            // 2-byte sequences
            ("2-byte U+0080", vec![0xC2, 0x80]),
            ("2-byte U+07FF", vec![0xDF, 0xBF]),
            // 3-byte sequences
            ("3-byte U+0800", vec![0xE0, 0xA0, 0x80]),
            ("3-byte U+D7FF", vec![0xED, 0x9F, 0xBF]),
            ("3-byte U+E000", vec![0xEE, 0x80, 0x80]),
            ("3-byte U+FFFF", vec![0xEF, 0xBF, 0xBF]),
            // 4-byte sequences
            ("4-byte U+10000", vec![0xF0, 0x90, 0x80, 0x80]),
            ("4-byte U+10FFFF", vec![0xF4, 0x8F, 0xBF, 0xBF]),
            // Mixed
            ("mixed ASCII and 2-byte", vec![b'a', 0xC2, 0x80, b'b']),
            ("euro sign", vec![0xE2, 0x82, 0xAC]),
            ("emoji", vec![0xF0, 0x9F, 0x98, 0x80]),
        ];

        for (name, bytes) in valid_cases {
            if bytes.is_empty() {
                continue;
            }

            let pred = validate_string(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, &bytes).unwrap();

            assert_eq!(
                out, true,
                "Expected valid UTF-8 for case '{}': {:02X?}",
                name, bytes
            );
        }
    }

    #[test]
    fn test_validate_number_valid() {
        let valid_cases = vec![
            // Integers
            "0",
            "1",
            "9",
            "10",
            "123",
            "999999",
            // Negative integers
            "-0",
            "-1",
            "-123",
            // Decimals
            "0.0",
            "0.1",
            "0.123",
            "1.0",
            "1.23",
            "123.456",
            "-0.0",
            "-1.23",
            // Exponents
            "1e0",
            "1e1",
            "1e10",
            "1E0",
            "1E10",
            "1e+0",
            "1e-0",
            "1e+10",
            "1e-10",
            "0e0",
            "-1e0",
            // Decimals with exponents
            "1.0e0",
            "1.23e4",
            "1.23e+4",
            "1.23e-4",
            "1.23E4",
            "-1.23e-4",
            // Edge cases
            "0.0e0",
            "123456789",
        ];

        for input in valid_cases {
            let bytes = input.as_bytes();
            let pred = validate_number(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(out, "Expected valid number for '{}'", input);
        }
    }

    #[test]
    fn test_validate_number_invalid() {
        let invalid_cases = vec![
            // Leading zeros (invalid in JSON)
            "01", "00", "007", "-01", // Missing digits
            ".", "-", "e", "E", ".1",  // no leading digit
            "1.",  // trailing dot
            "1e",  // trailing e
            "1e+", // trailing sign
            "1e-", // trailing sign
            "-.",  // minus then dot
            // Invalid characters
            "+1", // leading plus (not allowed in JSON)
            "1a", "1.2.3", "1ee1", "1e1e1", // Spaces (not part of number)
            " 1", "1 ",
            // Empty
            // "", // can't test empty - asserts
        ];

        for input in invalid_cases {
            let bytes = input.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            let pred = validate_number(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(!out, "Expected invalid number for '{}'", input);
        }
    }

    #[test]
    fn test_validate_integer_valid() {
        let valid_cases = vec![
            "0",
            "1",
            "9",
            "00",
            "01",
            "10",
            "42",
            "99",
            "123",
            "999",
            "0000",
            "1234",
            "9999",
            "123456789",
            "00000000000",
        ];

        for input in valid_cases {
            let bytes = input.as_bytes();
            let pred = validate_integer(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(out, "Expected valid integer for '{}'", input);
        }
    }

    #[test]
    fn test_validate_integer_invalid() {
        let invalid_cases = vec![
            // Non-digit characters
            "-1", "+1", "1.0", "1e0", "a", "1a", "a1", " 1", "1 ", ".", "-", "+", "hello", "12 34",
            "12.34", "0x10",
        ];

        for input in invalid_cases {
            let bytes = input.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            let pred = validate_integer(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(!out, "Expected invalid integer for '{}'", input);
        }
    }
}
