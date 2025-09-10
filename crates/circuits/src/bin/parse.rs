use mpz_circuits::Circuit;
use std::fs::write;

fn main() {
    build_aes();
    build_sha();
    #[cfg(feature = "blake3")]
    build_blake3();
}

fn build_aes() {
    let circ = Circuit::parse("circuits/bristol/aes_128_reverse.txt").unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write("circuits/bin/aes_128.bin", bytes).unwrap();
}

fn build_sha() {
    let circ = Circuit::parse("circuits/bristol/sha256_reverse.txt").unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write("circuits/bin/sha256.bin", bytes).unwrap();
}

#[cfg(feature = "blake3")]
fn build_blake3() {
    let circ = mpz_circuits::circuits::blake3::compress();

    let bytes = bincode::serialize(&circ).unwrap();
    write("circuits/bin/blake3.bin", bytes).unwrap();
}
