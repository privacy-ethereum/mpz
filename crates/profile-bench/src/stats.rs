use std::{cmp::Reverse, collections::HashMap};

use mpz_vm_core::{Directive, Op};
use mpz_vm_ir::{ExportKind, Function, Instruction, InstructionArith, LoadKind, Module, StoreKind};
use serde::Serialize;

use crate::tracer::TraceEvent;

#[derive(Serialize, Clone)]
pub struct CfRegion {
    pub private_cf: bool,
    pub ops: usize,
}

#[derive(Serialize)]
pub struct Stats {
    pub public_cf_ops: usize,
    pub private_cf_ops: usize,
    pub private_cf_count: usize,
    pub call_count: usize,
    pub decode_count: usize,
    pub memory_loads: usize,
    pub memory_stores: usize,
    pub public_cf_histogram: HashMap<String, usize>,
    pub private_cf_histogram: HashMap<String, usize>,
}

#[derive(Serialize)]
pub struct BlockInfo {
    pub func_idx: u32,
    pub func_name: String,
    pub block_idx: u32,
    pub instruction_count: usize,
    pub histogram: HashMap<String, usize>,
    pub exec_count: usize,
}

#[derive(Serialize)]
pub struct CallInfo {
    pub func_idx: u32,
    pub func_name: String,
    pub call_count: usize,
}

pub fn collect(trace: &[TraceEvent]) -> (Stats, Vec<CfRegion>) {
    let mut stats = Stats {
        public_cf_ops: 0,
        private_cf_ops: 0,
        private_cf_count: 0,
        call_count: 0,
        decode_count: 0,
        memory_loads: 0,
        memory_stores: 0,
        public_cf_histogram: HashMap::new(),
        private_cf_histogram: HashMap::new(),
    };

    let mut in_private_cf = false;
    let mut regions: Vec<CfRegion> = Vec::new();

    for event in trace {
        match event {
            TraceEvent::PrivateControlFlowStart => {
                stats.private_cf_count += 1;
                in_private_cf = true;
            }
            TraceEvent::PrivateControlFlowEnd => {
                in_private_cf = false;
            }
            TraceEvent::Directive(directive) => match directive {
                Directive::Op(op) => {
                    let name = op_name(op);
                    if matches!(op, Op::Load { .. }) {
                        stats.memory_loads += 1;
                    }
                    if matches!(op, Op::Store { .. }) {
                        stats.memory_stores += 1;
                    }
                    // Track CF regions.
                    match regions.last_mut() {
                        Some(r) if r.private_cf == in_private_cf => r.ops += 1,
                        _ => regions.push(CfRegion {
                            private_cf: in_private_cf,
                            ops: 1,
                        }),
                    }
                    if in_private_cf {
                        stats.private_cf_ops += 1;
                        *stats.private_cf_histogram.entry(name).or_insert(0) += 1;
                    } else {
                        stats.public_cf_ops += 1;
                        *stats.public_cf_histogram.entry(name).or_insert(0) += 1;
                    }
                }
                Directive::Call { .. } => {
                    stats.call_count += 1;
                }
                _ => {}
            },
        }
    }

    (stats, regions)
}

pub fn collect_blocks(module: &Module, trace: &[TraceEvent]) -> Vec<BlockInfo> {
    let func_names = build_func_names(module);

    // Build static instruction histograms per (func_idx, block_idx).
    let mut block_map: HashMap<(u32, u32), (usize, HashMap<String, usize>)> = HashMap::new();

    for (func_idx, func) in module.functions().iter().enumerate() {
        let func = match func {
            Function::Local(f) => f,
            _ => continue,
        };
        let body = func.body();
        for (block_idx, block) in body.blocks.iter().enumerate() {
            let mut histogram = HashMap::new();
            for instr in &block.body {
                let name = instruction_name(instr);
                *histogram.entry(name).or_insert(0) += 1;
            }
            let count = block.body.len();
            block_map.insert((func_idx as u32, block_idx as u32), (count, histogram));
        }
    }

    // Count block executions from trace.
    let mut exec_counts: HashMap<(u32, u32), usize> = HashMap::new();
    for event in trace {
        if let TraceEvent::Directive(Directive::Branch {
            func_idx, block, ..
        }) = event
        {
            *exec_counts.entry((*func_idx, block.0)).or_insert(0) += 1;
        }
    }

    // Build result: only executed blocks with at least one instruction.
    let mut blocks: Vec<BlockInfo> = exec_counts
        .into_iter()
        .filter_map(|((func_idx, block_idx), exec_count)| {
            let (instruction_count, histogram) = block_map.remove(&(func_idx, block_idx))?;
            if instruction_count == 0 {
                return None;
            }
            let func_name = func_names
                .get(&func_idx)
                .map(|n| demangle(n))
                .unwrap_or_else(|| format!("func_{}", func_idx));
            Some(BlockInfo {
                func_idx,
                func_name,
                block_idx,
                instruction_count,
                histogram,
                exec_count,
            })
        })
        .collect();

    blocks.sort_by_key(|b| Reverse(b.exec_count));
    blocks
}

pub fn collect_calls(module: &Module, trace: &[TraceEvent]) -> Vec<CallInfo> {
    let func_names = build_func_names(module);

    let mut counts: HashMap<u32, usize> = HashMap::new();
    for event in trace {
        if let TraceEvent::Directive(Directive::Call { func_idx, .. }) = event {
            *counts.entry(*func_idx).or_insert(0) += 1;
        }
    }

    let mut calls: Vec<CallInfo> = counts
        .into_iter()
        .map(|(func_idx, call_count)| {
            let func_name = func_names
                .get(&func_idx)
                .map(|n| demangle(n))
                .unwrap_or_else(|| format!("func_{}", func_idx));
            CallInfo {
                func_idx,
                func_name,
                call_count,
            }
        })
        .collect();
    calls.sort_by_key(|c| Reverse(c.call_count));
    calls
}

/// Builds a `func_idx -> name` map, preferring the name section, then exports,
/// then imports.
fn build_func_names(module: &Module) -> HashMap<u32, String> {
    let mut func_names: HashMap<u32, String> = HashMap::new();
    for (idx, func) in module.functions().iter().enumerate() {
        if let Function::Import(f) = func {
            func_names.insert(idx as u32, f.name().to_string());
        }
    }
    for export in module.exports() {
        if let ExportKind::Func(idx) = export.kind {
            func_names.insert(idx, export.name.clone());
        }
    }
    // Name section overrides (most specific).
    for (idx, name) in module.function_names() {
        func_names.insert(*idx, name.clone());
    }
    func_names
}

/// Demangles a Rust symbol and strips the trailing `::hash` disambiguator.
fn demangle(name: &str) -> String {
    let demangled = rustc_demangle::demangle(name).to_string();
    if let Some(idx) = demangled.rfind("::h")
        && demangled[idx + 3..].chars().all(|c| c.is_ascii_hexdigit())
    {
        return demangled[..idx].to_string();
    }
    demangled
}

pub fn instruction_name(instr: &Instruction) -> String {
    match instr {
        Instruction::Nop => "Nop".into(),
        Instruction::Call { .. } => "Call".into(),
        Instruction::CallIndirect { .. } => "CallIndirect".into(),
        Instruction::Select { .. } => "Select".into(),
        Instruction::Copy { .. } => "Copy".into(),
        Instruction::GlobalGet { .. } => "GlobalGet".into(),
        Instruction::GlobalSet { .. } => "GlobalSet".into(),
        Instruction::Load { kind, .. } => load_name(*kind),
        Instruction::Store { kind, .. } => store_name(*kind),
        Instruction::MemorySize { .. } => "MemorySize".into(),
        Instruction::MemoryGrow { .. } => "MemoryGrow".into(),
        Instruction::MemoryFill { .. } => "MemoryFill".into(),
        Instruction::MemoryCopy { .. } => "MemoryCopy".into(),
        Instruction::MemoryInit { .. } => "MemoryInit".into(),
        Instruction::DataDrop { .. } => "DataDrop".into(),
        Instruction::I32Const { .. } => "I32Const".into(),
        Instruction::I64Const { .. } => "I64Const".into(),
        Instruction::F32Const { .. } => "F32Const".into(),
        Instruction::F64Const { .. } => "F64Const".into(),
        Instruction::RefNull { .. } => "RefNull".into(),
        Instruction::RefIsNull { .. } => "RefIsNull".into(),
        Instruction::RefFunc { .. } => "RefFunc".into(),
        Instruction::Arith(InstructionArith::Unary(u)) => format!("{:?}", u.op),
        Instruction::Arith(InstructionArith::Binary(b)) => format!("{:?}", b.op),
    }
}

pub fn op_name(op: &Op) -> String {
    match op {
        Op::Copy { .. } => "Copy".into(),
        Op::GlobalGet { .. } => "GlobalGet".into(),
        Op::GlobalSet { .. } => "GlobalSet".into(),
        Op::Select { .. } => "Select".into(),
        Op::Unary { op, .. } => format!("{:?}", op),
        Op::Binary { op, .. } => format!("{:?}", op),
        Op::Load { kind, .. } => load_name(*kind),
        Op::Store { kind, .. } => store_name(*kind),
        Op::MemoryFill { .. } => "MemoryFill".into(),
        Op::MemoryCopy { .. } => "MemoryCopy".into(),
        Op::MemoryInit { .. } => "MemoryInit".into(),
    }
}

fn load_name(kind: LoadKind) -> String {
    format!("Load({kind:?})")
}

fn store_name(kind: StoreKind) -> String {
    format!("Store({kind:?})")
}
