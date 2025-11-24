use std::array::from_fn;

use itybity::ToBits;
use mpz_circuits::{Circuit, CircuitBuilder, Feed, Node, ops};

type Byte = [Node<Feed>; 8];
type Bool = Node<Feed>;

fn literal(builder: &mut CircuitBuilder, value: u8) -> Byte {
    let mut bits = value.iter_lsb0();

    from_fn(|_| {
        let bit = bits.next().unwrap();
        if bit {
            builder.get_const_one()
        } else {
            builder.get_const_zero()
        }
    })
}

fn eq_any(builder: &mut CircuitBuilder, lhs: &Byte, rhs: &[u8]) -> Bool {
    let mut eq = Vec::with_capacity(rhs.len());
    for rhs in rhs {
        let rhs = literal(builder, *rhs);
        eq.push(ops::eq(builder, *lhs, rhs));
    }

    ops::any(builder, &eq)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ByteData {
        byte: Byte,
        is_ctrl: Option<Bool>,
        is_quote: Option<Bool>,
        is_escape: Option<Bool>,
        is_unicode: Option<Bool>,
        is_valid_escape: Option<Bool>,
        is_hex: Option<Bool>,
    }

    impl ByteData {
        fn new(builder: &mut CircuitBuilder) -> Self {
            let byte = from_fn(|_| builder.add_input());
            Self {
                byte,
                is_ctrl: None,
                is_quote: None,
                is_escape: None,
                is_unicode: None,
                is_valid_escape: None,
                is_hex: None,
            }
        }

        fn is_ctrl(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self.is_ctrl.get_or_insert_with(|| {
                let char_ctrl = literal(builder, 0x1F);
                ops::lte(builder, self.byte, char_ctrl)
            })
        }

        fn is_quote(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self.is_quote.get_or_insert_with(|| {
                let char_quote = literal(builder, b'"');
                ops::eq(builder, self.byte, char_quote)
            })
        }

        fn is_escape(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self.is_escape.get_or_insert_with(|| {
                let char_escape = literal(builder, b'\\');
                ops::eq(builder, self.byte, char_escape)
            })
        }

        fn is_unicode_escape_suffix(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self.is_unicode.get_or_insert_with(|| {
                let char_unicode = literal(builder, b'u');
                ops::eq(builder, self.byte, char_unicode)
            })
        }

        fn is_escape_suffix(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self
                .is_valid_escape
                .get_or_insert_with(|| eq_any(builder, &self.byte, b"\"/\\bfnrt")) // unicode is handled separately
        }

        fn is_hex(&mut self, builder: &mut CircuitBuilder) -> Bool {
            *self.is_hex.get_or_insert_with(|| {
                let mut in_range = Vec::with_capacity(3);
                for (start, end) in [(b'0', b'9'), (b'a', b'f'), (b'A', b'F')] {
                    let start = literal(builder, start);
                    let end = literal(builder, end);

                    let gte = ops::gte(builder, self.byte, start);
                    let lte = ops::lte(builder, self.byte, end);

                    in_range.push(builder.add_and_gate(gte, lte));
                }

                ops::all(builder, &in_range)
            })
        }
    }

    #[test]
    fn test_compile() {
        for len in [16, 128, 1024] {
            let mut builder = CircuitBuilder::new();

            let mut data: Vec<ByteData> = (0..len).map(|_| ByteData::new(&mut builder)).collect();
            let mut is_string = Vec::with_capacity(len);

            for i in 0..len {
                let byte = &mut data[i];

                let is_ctrl = byte.is_ctrl(&mut builder);
                let is_not_ctrl = builder.add_inv_gate(is_ctrl);
                let is_quote = byte.is_quote(&mut builder);
                let is_not_quote = builder.add_inv_gate(is_quote);
                let is_escape = byte.is_escape(&mut builder);
                let is_not_escape = builder.add_inv_gate(is_escape);

                // If this is a quote character, it must be preceded by an escape.
                let allow_quote = i > 0;
                let is_valid_quote = if allow_quote {
                    data[i - 1].is_escape(&mut builder)
                } else {
                    is_not_quote
                };

                // If this is an escape character, there must be at least one more byte.
                let allow_escape = len - i > 1;
                let is_valid_escape = if allow_escape {
                    let next_is_escape_suffix = data[i + 1].is_escape_suffix(&mut builder);

                    let next_is_unicode = data[i + 1].is_unicode_escape_suffix(&mut builder);
                    let next_is_not_unicode = builder.add_inv_gate(next_is_unicode);
                    // If it is unicode, there must be at least 5 more bytes \uXXXX
                    let allow_unicode = len - i > 5;
                    let is_valid_unicode = if allow_unicode {
                        let is_hex_0 = data[i + 2].is_hex(&mut builder);
                        let is_hex_1 = data[i + 3].is_hex(&mut builder);
                        let is_hex_2 = data[i + 4].is_hex(&mut builder);
                        let is_hex_3 = data[i + 5].is_hex(&mut builder);

                        ops::all(
                            &mut builder,
                            &[next_is_unicode, is_hex_0, is_hex_1, is_hex_2, is_hex_3],
                        )
                    } else {
                        next_is_not_unicode
                    };

                    ops::any(&mut builder, &[next_is_escape_suffix, is_valid_unicode])
                } else {
                    is_not_escape
                };

                is_string.push(ops::all(
                    &mut builder,
                    &[is_not_ctrl, is_valid_quote, is_valid_escape],
                ));
            }

            let out = ops::all(&mut builder, &is_string);

            builder.add_output(out);

            let circuit = builder.build().unwrap();

            println!(
                "string length: {}, gate count {} ({} AND)",
                len,
                circuit.gates().len(),
                circuit.and_count()
            );
        }
    }
}
