//! One-off analysis: classify `Copy` instructions in the IR and weight them by
//! runtime execution counts to estimate how many copies a producer→copy
//! coalescing pass would eliminate.
//!
//! Run after building the wasm guest and running the profiler:
//!   cargo run -p profile-bench --example copy_analysis -- json_parse

use std::collections::HashMap;

use mpz_vm_ir::{Function, Instruction, InstructionArith, Module, Reg};
use serde_json::Value as Json;

const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/wasm/profile_bench_programs.wasm"
);

fn dst_of(instr: &Instruction) -> Option<Reg> {
    use Instruction::*;
    match instr {
        Call { dst, .. } | CallIndirect { dst, .. } => *dst,
        Select { dst, .. }
        | Copy { dst, .. }
        | GlobalGet { dst, .. }
        | Load { dst, .. }
        | MemorySize { dst }
        | MemoryGrow { dst, .. }
        | I32Const { dst, .. }
        | I64Const { dst, .. }
        | F32Const { dst, .. }
        | F64Const { dst, .. }
        | RefNull { dst, .. }
        | RefIsNull { dst, .. }
        | RefFunc { dst, .. } => Some(*dst),
        Arith(InstructionArith::Unary(u)) => Some(u.dst),
        Arith(InstructionArith::Binary(b)) => Some(b.dst),
        _ => None,
    }
}

/// Returns true if `r` appears anywhere in `instr` (as a read operand or dst).
fn mentions(instr: &Instruction, r: Reg) -> bool {
    use Instruction::*;
    let mut hit = dst_of(instr) == Some(r);
    let mut chk = |x: &Reg| hit |= *x == r;
    match instr {
        Call { args, .. } => args.iter().for_each(&mut chk),
        CallIndirect { table_idx, args, .. } => {
            chk(table_idx);
            args.iter().for_each(&mut chk);
        }
        Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            chk(cond);
            chk(if_true);
            chk(if_false);
        }
        Copy { src, .. } => chk(src),
        GlobalSet { src, .. } => chk(src),
        Load { addr, .. } => chk(addr),
        Store { addr, val, .. } => {
            chk(addr);
            chk(val);
        }
        MemoryGrow { pages, .. } => chk(pages),
        MemoryFill { dest, val, len } => {
            chk(dest);
            chk(val);
            chk(len);
        }
        MemoryCopy { dest, src, len } => {
            chk(dest);
            chk(src);
            chk(len);
        }
        MemoryInit {
            dest,
            src_offset,
            len,
            ..
        } => {
            chk(dest);
            chk(src_offset);
            chk(len);
        }
        RefIsNull { src, .. } => chk(src),
        Arith(InstructionArith::Unary(u)) => chk(&u.src),
        Arith(InstructionArith::Binary(b)) => {
            chk(&b.lhs);
            chk(&b.rhs);
        }
        _ => {}
    }
    hit
}

fn num_locals(func: &mpz_vm_ir::LocalFunction) -> u32 {
    func.func_type().params.len() as u32 + func.locals().iter().map(|l| l.count).sum::<u32>()
}

/// Classifies a `Copy` at index `i` in `body` as coalescable: the previous
/// instruction produces the copy's `src`, `src` is a temporary, and `src` is
/// dead after the copy. Such a copy can be removed by redirecting the producer
/// to write the copy's `dst` directly.
fn is_coalescable(body: &[Instruction], i: usize, num_locals: u32) -> bool {
    let Instruction::Copy { dst, src } = body[i] else {
        return false;
    };
    if dst == src || i == 0 {
        return false;
    }
    // Source must be a temporary (single-assignment within its short live range).
    if src.0 < num_locals {
        return false;
    }
    // Previous instruction must produce `src`.
    if dst_of(&body[i - 1]) != Some(src) {
        return false;
    }
    // `src` must be dead after the copy.
    !body[i + 1..].iter().any(|instr| mentions(instr, src))
}

fn main() {
    let filter = std::env::args().nth(1).unwrap_or_else(|| "json_parse".into());

    let wasm = std::fs::read(WASM_PATH).expect("build wasm first");
    let module = Module::parse(&wasm).expect("parse");

    // Load runtime exec counts from the profiler's JSON output.
    let json_path = format!(
        "{}/output/{}.json",
        env!("CARGO_MANIFEST_DIR"),
        filter
    );
    let json: Json = serde_json::from_slice(&std::fs::read(&json_path).expect("run profiler first"))
        .expect("json");
    let mut exec: HashMap<(u32, u32), u64> = HashMap::new();
    for b in json["blocks"].as_array().unwrap() {
        let f = b["func_idx"].as_u64().unwrap() as u32;
        let bl = b["block_idx"].as_u64().unwrap() as u32;
        exec.insert((f, bl), b["exec_count"].as_u64().unwrap());
    }

    let mut rt_total = 0u64;
    let mut rt_local_dst = 0u64; // copies whose dst is a local register
    let mut rt_src_temp = 0u64; // src is a temporary
    let mut rt_src_local = 0u64; // src is another local (local->local copy)
    let mut rt_src_temp_adj = 0u64; // src temp AND prev instr produces it
    let mut rt_src_temp_adj_dead = 0u64; // ...AND src dead after (== coalescable)
    let mut rt_tee_elim = 0u64; // tee-style: eliminable by produce-into-local + alias
    let mut st_total = 0u64;
    let mut st_coalescable = 0u64;

    // Track the hottest copy-containing block to dump.
    let mut hottest: Option<(u64, usize, usize)> = None; // (weight, func_idx, block_idx)

    for (func_idx, func) in module.functions().iter().enumerate() {
        let Function::Local(f) = func else { continue };
        let nl = num_locals(f);
        for (block_idx, block) in f.body().blocks.iter().enumerate() {
            let weight = exec
                .get(&(func_idx as u32, block_idx as u32))
                .copied()
                .unwrap_or(0);
            let has_copy = block
                .body
                .iter()
                .any(|i| matches!(i, Instruction::Copy { .. }));
            if has_copy && hottest.map_or(true, |(w, ..)| weight > w) {
                hottest = Some((weight, func_idx, block_idx));
            }
            for (i, instr) in block.body.iter().enumerate() {
                let Instruction::Copy { dst, src } = *instr else {
                    continue;
                };
                st_total += 1;
                rt_total += weight;
                if dst.0 < nl {
                    rt_local_dst += weight;
                }
                if src.0 >= nl {
                    rt_src_temp += weight;
                    if i > 0 && dst_of(&block.body[i - 1]) == Some(src) {
                        rt_src_temp_adj += weight;
                        // Tee-coalescable: redirect producer to write `dst`, alias
                        // subsequent uses of `src` to `dst`. Safe within the block
                        // when `dst` is not reassigned afterward (so the alias stays
                        // valid) — `materialize_local` already handles cross-write
                        // hazards for the carried local.
                        if !block.body[i + 1..]
                            .iter()
                            .any(|x| dst_of(x) == Some(dst))
                        {
                            rt_tee_elim += weight;
                        }
                        if !block.body[i + 1..].iter().any(|x| mentions(x, src)) {
                            rt_src_temp_adj_dead += weight;
                        }
                    }
                } else {
                    rt_src_local += weight;
                }
                if is_coalescable(&block.body, i, nl) {
                    st_coalescable += 1;
                }
            }
        }
    }

    println!("=== Copy analysis for `{filter}` ===");
    println!("static copies:            {st_total}");
    println!("static coalescable:       {st_coalescable} ({:.1}%)", pct(st_coalescable, st_total));
    println!();
    println!("runtime copies (weighted): {rt_total}");
    println!("  dst is a local:          {rt_local_dst} ({:.1}%)", pct(rt_local_dst, rt_total));
    println!("  src is a temp:           {rt_src_temp} ({:.1}%)", pct(rt_src_temp, rt_total));
    println!("    ...prev produces src:  {rt_src_temp_adj} ({:.1}%)", pct(rt_src_temp_adj, rt_total));
    println!("    ...and src dead after: {rt_src_temp_adj_dead} ({:.1}%)  <- simple copy-elision", pct(rt_src_temp_adj_dead, rt_total));
    println!("    ...tee-eliminable:     {rt_tee_elim} ({:.1}%)  <- produce-into-local + alias", pct(rt_tee_elim, rt_total));
    println!("  src is a local:          {rt_src_local} ({:.1}%)", pct(rt_src_local, rt_total));
    println!("  remaining after pass:    {} ({:.1}%)", rt_total - rt_tee_elim, pct(rt_total - rt_tee_elim, rt_total));

    if let Some((w, fi, bi)) = hottest {
        let f = module.functions()[fi].as_local().unwrap();
        let nl = num_locals(f);
        println!("\n=== hottest copy block: func {fi} block {bi}, exec {w}, num_locals {nl} ===");
        for instr in &f.body().blocks[bi].body {
            println!("  {instr:?}");
        }
    }
}

fn pct(a: u64, b: u64) -> f64 {
    if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 }
}
