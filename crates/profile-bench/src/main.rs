mod bench;
mod benches;

use std::path::PathBuf;

use mpz_vm_ir::Module;
use profile_core::stats;

use crate::bench::BenchmarkDef;

const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/wasm/profile_bench_programs.wasm"
);

fn main() {
    let filter: Option<String> = std::env::args().nth(1);

    let wasm_path = PathBuf::from(WASM_PATH);
    if !wasm_path.exists() {
        eprintln!(
            "WASM binary not found at {}\nRun ./crates/profile-bench/build-wasm.sh first.",
            wasm_path.display()
        );
        std::process::exit(1);
    }

    let wasm_bytes = std::fs::read(&wasm_path).expect("wasm file should be readable");
    let module = Module::parse(&wasm_bytes).expect("wasm should parse");

    let benchmarks: Vec<&BenchmarkDef> = inventory::iter::<BenchmarkDef>
        .into_iter()
        .filter(|b| filter.as_deref().is_none_or(|f| b.name.contains(f)))
        .collect();

    if benchmarks.is_empty() {
        eprintln!("No benchmarks registered.");
        std::process::exit(1);
    }

    println!(
        "{:<24} | {:>12} | {:>12} | {:>10} | {:>9} | {:>9} | {:>7} | {:>7} | Result",
        "Benchmark", "Public CF", "Private CF", "Priv CF Rgn", "Mem Ld", "Mem St", "Calls", "Decode",
    );
    println!("{}", "-".repeat(120));

    for def in &benchmarks {
        let output = (def.run)(&module);
        let (s, _regions) = stats::collect(&output.trace);
        println!(
            "{:<24} | {:>12} | {:>12} | {:>10} | {:>9} | {:>9} | {:>7} | {:>7} | {}",
            def.name,
            s.public_cf_ops,
            s.private_cf_ops,
            s.private_cf_count,
            s.memory_loads,
            s.memory_stores,
            s.call_count,
            s.decode_count,
            output.outcome,
        );
    }
}
