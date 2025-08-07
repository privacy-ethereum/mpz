use mpz_circuits::Circuit;
use std::fs::write;

fn main() {
    build_aes();
    build_sha();
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
