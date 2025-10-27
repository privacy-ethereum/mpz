use mpz_circuits::Circuit;
use std::{fs::write, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../circuits/bristol");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    #[cfg(feature = "aes")]
    build_aes(&manifest_dir);
    #[cfg(feature = "sha2")]
    build_sha(&manifest_dir);
    #[cfg(feature = "blake3")]
    build_blake3(&manifest_dir);
}

fn build_aes(manifest_dir: &String) {
    let path = PathBuf::from(manifest_dir).join("../circuits/bristol/aes_128_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    let path = PathBuf::from(manifest_dir).join("../circuits/bin/aes_128.bin");
    write(path.as_path(), bytes).unwrap();

    let path = PathBuf::from(manifest_dir).join("../circuits/bristol/aes_128_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    let path = PathBuf::from(manifest_dir).join("../circuits/bin/aes_128_ks.bin");
    write(path.as_path(), bytes).unwrap();

    let path =
        PathBuf::from(manifest_dir).join("../circuits/bristol/aes_128_post_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    let path = PathBuf::from(manifest_dir).join("../circuits/bin/aes_128_post_ks.bin");
    write(path.as_path(), bytes).unwrap();
}

fn build_sha(manifest_dir: &String) {
    let path = PathBuf::from(manifest_dir).join("../circuits/bristol/sha256_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write("../circuits/bin/sha256.bin", bytes).unwrap();
}

#[cfg(feature = "blake3")]
fn build_blake3(manifest_dir: &String) {
    let circ = mpz_circuits::circuits::blake3::compress();

    let bytes = bincode::serialize(&circ).unwrap();
    let path = PathBuf::from(manifest_dir).join("../circuits/bin/blake3.bin");
    write(path.as_path(), bytes).unwrap();
}
