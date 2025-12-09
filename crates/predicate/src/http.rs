//! Pre-built predicates for HTTP validation.

use crate::{ne, Pred};
use rangeset::prelude::RangeSet;

/// Builds a predicate that validates an HTTP header value.
///
/// HTTP header values must not contain carriage return (`\r`, ASCII 13).
pub fn validate_header_value(range: RangeSet<usize>) -> Pred {
    let preds: Vec<Pred> = range.iter_values().map(|idx| ne(idx, b'\r')).collect();
    Pred::and(preds)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::compiler::Compiler;
    use mpz_circuits::evaluate;

    #[test]
    fn test_validate_header_value_valid() {
        let valid_cases = vec![
            "application/json",
            "text/html; charset=utf-8",
            "Bearer token123",
            "gzip, deflate",
            "Mon, 01 Jan 2024 00:00:00 GMT",
            "bytes=0-1023",
            "*/*",
            "keep-alive",
            "no-cache",
            "https://example.com",
            "hello world",
            "value\twith\ttabs",  // tabs are allowed
            "value with spaces",
        ];

        for input in valid_cases {
            let bytes = input.as_bytes();
            let pred = validate_header_value(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(out, "Expected valid header value for '{}'", input);
        }
    }

    #[test]
    fn test_validate_header_value_invalid() {
        let invalid_cases = vec![
            ("value\r\ninjection", "contains CRLF"),
            ("value\ronly", "contains CR"),
            ("\rstart", "starts with CR"),
            ("end\r", "ends with CR"),
            ("mid\rdle", "CR in middle"),
        ];

        for (input, desc) in invalid_cases {
            let bytes = input.as_bytes();
            let pred = validate_header_value(RangeSet::from(0..bytes.len()));
            let circ = Compiler::new().compile(&pred);
            let out: bool = evaluate!(circ, bytes).unwrap();

            assert!(!out, "Expected invalid header value for '{}' ({})", input, desc);
        }
    }
}
