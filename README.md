[![CI](https://github.com/privacy-scaling-explorations/mpz/actions/workflows/rust.yml/badge.svg)](https://github.com/privacy-scaling-explorations/mpz/actions)

# MPZ

mpz is a collection of multi-party computation libraries written in Rust 🦀.

This project strives to provide safe, performant, modular and portable MPC software with a focus on usability.

See [our design doc](./DESIGN.md) for information on design choices, standards and project structure.

## ⚠️ Notice

This project is currently under active development and should not be used in production. Expect bugs and regular major breaking changes. Use at your own risk.

## Crates

  - [`mpz-core`](./crates/mpz-core/) - Core cryptographic primitives.
  - [`mpz-common`](./crates/mpz-common) - Common functionalities needed for modeling protocol execution, I/O, and multi-threading.
  - [`mpz-fields`](./crates/mpz-fields/) - Finite-fields.
  - [`mpz-circuits`](./crates/mpz-circuits/) ([`macros`](./crates/mpz-circuits-macros/)) - Boolean circuit DSL.
  - [`mpz-ot`](./crates/mpz-ot) ([`core`](./crates/mpz-ot-core/)) - Oblivious transfer protocols.
  - [`mpz-garble`](./crates/mpz-garble/) ([`core`](./crates/mpz-garble-core/)) - Boolean garbled circuit protocols.
  - [`mpz-share-conversion`](./crates/mpz-share-conversion/) ([`core`](./crates/mpz-share-conversion-core/)) - Multiplicative-to-Additive and Additive-to-Multiplicative share conversion protocols for a variety of fields.
  - [`mpz-cointoss`](./crates/mpz-cointoss/) ([`core`](./crates/mpz-cointoss-core/)) - 2-party cointoss protocol.
  - [`matrix-transpose`](./crates/matrix-transpose/) - Bit-wise matrix transposition.
  - [`clmul`](./crates/clmul/) - Carry-less multiplication.

## License
All crates in this repository are licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributors

- [TLSNotary](https://github.com/tlsnotary)
- [PADO Labs](https://github.com/pado-labs)


### Pronunciation

mpz is pronounced "em-peasy".