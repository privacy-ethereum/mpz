mod bench;
mod benches;
mod render;
mod stats;
mod tracer;

use std::path::PathBuf;

use mpz_vm_ir::Module;

use crate::{
    bench::BenchmarkDef,
    stats::{BlockInfo, CallInfo, CfRegion, Stats},
};

const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/wasm/profile_bench_programs.wasm"
);

struct RenderedBench {
    stats: Stats,
    regions: Vec<CfRegion>,
    blocks: Vec<BlockInfo>,
    calls: Vec<CallInfo>,
    outcome: String,
}

fn execute(module: &Module, def: &BenchmarkDef) -> RenderedBench {
    let output = (def.run)(module);
    let (stats, regions) = stats::collect(&output.trace);
    let blocks = stats::collect_blocks(module, &output.trace);
    let calls = stats::collect_calls(module, &output.trace);
    RenderedBench {
        stats,
        regions,
        blocks,
        calls,
        outcome: output.outcome,
    }
}

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

    // Header
    println!(
        "{:<24} | {:>12} | {:>12} | {:>10} | {:>9} | {:>9} | {:>7} | {:>7} | Result",
        "Benchmark",
        "Public CF",
        "Private CF",
        "Priv CF Rgn",
        "Mem Ld",
        "Mem St",
        "Calls",
        "Decode",
    );
    println!("{}", "-".repeat(120));

    let results: Vec<_> = benchmarks
        .iter()
        .map(|def| {
            let result = execute(&module, def);
            println!(
                "{:<24} | {:>12} | {:>12} | {:>10} | {:>9} | {:>9} | {:>7} | {:>7} | {}",
                def.name,
                result.stats.public_cf_ops,
                result.stats.private_cf_ops,
                result.stats.private_cf_count,
                result.stats.memory_loads,
                result.stats.memory_stores,
                result.stats.call_count,
                result.stats.decode_count,
                result.outcome,
            );
            (def.name, result)
        })
        .collect();

    println!();

    // Generate JSON data files
    let output_dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/output"));
    std::fs::create_dir_all(&output_dir).expect("output dir should be creatable");

    for (name, result) in &results {
        let json = render::render_json(
            name,
            &result.stats,
            &result.regions,
            &result.blocks,
            &result.calls,
        );
        let path = output_dir.join(format!("{}.json", name));
        std::fs::write(&path, json).expect("json file should be writable");
    }
}
