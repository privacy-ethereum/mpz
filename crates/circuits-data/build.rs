use mpz_circuits_core::Circuit;
use std::{
    fs::write,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rerun-if-changed=../circuits-core/bristol");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let circuits_dir = PathBuf::from(manifest_dir).join("../circuits-core/bristol");
    build_aes(&circuits_dir);
    build_sha2(&circuits_dir);
    build_blake3();
    build_keccak(&circuits_dir);
}

fn build_aes(circuits_dir: &Path) {
    let path = circuits_dir.join("aes_128_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/aes_128.bin"), bytes).unwrap();

    let path = circuits_dir.join("aes_128_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/aes_128_ks.bin"), bytes).unwrap();

    let path = circuits_dir.join("aes_128_post_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/aes_128_post_ks.bin"), bytes).unwrap();
}

fn build_sha2(circuits_dir: &Path) {
    let path = circuits_dir.join("sha256_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/sha256.bin"), bytes).unwrap();
}

fn build_blake3() {
    let circ = mpz_circuits_core::circuits::blake3::compress();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/blake3.bin"), bytes).unwrap();
}

fn build_keccak(circuits_dir: &Path) {
    let path = circuits_dir.join("keccak_f.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(Path::new("data/keccak_f.bin"), bytes).unwrap();
}
