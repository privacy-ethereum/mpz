# LPN Estimator

This crate estimates the security of LPN instances, by computing the bit
security from different attacks based on <https://eprint.iacr.org/2022/712>.
So far exact and regular LPN over F_2 are supported.

- There exists a [reference
  implementation](https://github.com/tlsnotary/LPN-Estimator/blob/main/home/estimator.py)
  from the paper, which we forked from <https://github.com/RabbitCabbage/LPN-Estimator>
- `src/lpn.rs` is our own implementation

In `src/bin` there are executable binaries:

- `exact.rs` estimates the bit security for an exact LPN instance.
- `regular.rs` estimates the bit security for a regular LPN instance.
- `estimator.rs` does code generation by creating a static array of LPN
  instances satisfying a minium bit security. This is used in
  `crates/ot-core/ferret/config/`. For example `cargo run --release --bin
  estimator -- regular 128 1200 > ../ot-core/src/ferret/config/regular.rs`
  will do code generation for regular LPN instances.
