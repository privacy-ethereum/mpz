use std::collections::HashMap;

use ir::{BlockId, ExportKind, Function, Instruction, InstructionArith, Module};
use mpz_vm_core_new::{Directive, Op, ideal::TraceEvent};
use serde::Serialize;

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

impl Stats {
    pub fn empty() -> Self {
        Self {
            public_cf_ops: 0,
            private_cf_ops: 0,
            private_cf_count: 0,
            call_count: 0,
            decode_count: 0,
            memory_loads: 0,
            memory_stores: 0,
            public_cf_histogram: HashMap::new(),
            private_cf_histogram: HashMap::new(),
        }
    }
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

pub fn collect_calls(module: &Module, trace: &[TraceEvent]) -> Vec<CallInfo> {
    // Build func name map (same logic as collect_blocks).
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
    for (idx, name) in module.function_names() {
        func_names.insert(*idx, name.clone());
    }

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
                .map(|n| {
                    let demangled = rustc_demangle::demangle(n).to_string();
                    if let Some(idx) = demangled.rfind("::h") {
                        if demangled[idx + 3..].chars().all(|c| c.is_ascii_hexdigit()) {
                            return demangled[..idx].to_string();
                        }
                    }
                    demangled
                })
                .unwrap_or_else(|| format!("func_{}", func_idx));
            CallInfo {
                func_idx,
                func_name,
                call_count,
            }
        })
        .collect();
    calls.sort_by(|a, b| b.call_count.cmp(&a.call_count));
    calls
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
            TraceEvent::PrivateControlFlowStart { .. } => {
                stats.private_cf_count += 1;
                in_private_cf = true;
            }
            TraceEvent::PrivateControlFlowEnd => {
                in_private_cf = false;
            }
            TraceEvent::Directive(directive) => match directive {
                Directive::Op(op) => {
                    let name = op_name(op);
                    if is_load(op) {
                        stats.memory_loads += 1;
                    }
                    if is_store(op) {
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
    // Build func_idx -> name map. Prefer name section, then exports, then imports.
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
                .map(|n| {
                    let demangled = rustc_demangle::demangle(n).to_string();
                    // Strip the trailing ::hash suffix (e.g. ::h1a2b3c4d5e6f7890)
                    if let Some(idx) = demangled.rfind("::h") {
                        if demangled[idx + 3..].chars().all(|c| c.is_ascii_hexdigit()) {
                            return demangled[..idx].to_string();
                        }
                    }
                    demangled
                })
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

    blocks.sort_by(|a, b| b.exec_count.cmp(&a.exec_count));

    blocks
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
        Instruction::I32Load { .. } => "I32Load".into(),
        Instruction::I64Load { .. } => "I64Load".into(),
        Instruction::I32Load8S { .. } => "I32Load8S".into(),
        Instruction::I32Load8U { .. } => "I32Load8U".into(),
        Instruction::I32Load16S { .. } => "I32Load16S".into(),
        Instruction::I32Load16U { .. } => "I32Load16U".into(),
        Instruction::I64Load8S { .. } => "I64Load8S".into(),
        Instruction::I64Load8U { .. } => "I64Load8U".into(),
        Instruction::I64Load16S { .. } => "I64Load16S".into(),
        Instruction::I64Load16U { .. } => "I64Load16U".into(),
        Instruction::I64Load32S { .. } => "I64Load32S".into(),
        Instruction::I64Load32U { .. } => "I64Load32U".into(),
        Instruction::F32Load { .. } => "F32Load".into(),
        Instruction::F64Load { .. } => "F64Load".into(),
        Instruction::I32Store { .. } => "I32Store".into(),
        Instruction::I64Store { .. } => "I64Store".into(),
        Instruction::I32Store8 { .. } => "I32Store8".into(),
        Instruction::I32Store16 { .. } => "I32Store16".into(),
        Instruction::I64Store8 { .. } => "I64Store8".into(),
        Instruction::I64Store16 { .. } => "I64Store16".into(),
        Instruction::I64Store32 { .. } => "I64Store32".into(),
        Instruction::F32Store { .. } => "F32Store".into(),
        Instruction::F64Store { .. } => "F64Store".into(),
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
        Op::I32Load { .. } => "I32Load".into(),
        Op::I64Load { .. } => "I64Load".into(),
        Op::F32Load { .. } => "F32Load".into(),
        Op::F64Load { .. } => "F64Load".into(),
        Op::I32Load8S { .. } => "I32Load8S".into(),
        Op::I32Load8U { .. } => "I32Load8U".into(),
        Op::I32Load16S { .. } => "I32Load16S".into(),
        Op::I32Load16U { .. } => "I32Load16U".into(),
        Op::I64Load8S { .. } => "I64Load8S".into(),
        Op::I64Load8U { .. } => "I64Load8U".into(),
        Op::I64Load16S { .. } => "I64Load16S".into(),
        Op::I64Load16U { .. } => "I64Load16U".into(),
        Op::I64Load32S { .. } => "I64Load32S".into(),
        Op::I64Load32U { .. } => "I64Load32U".into(),
        Op::I32Store { .. } => "I32Store".into(),
        Op::I64Store { .. } => "I64Store".into(),
        Op::F32Store { .. } => "F32Store".into(),
        Op::F64Store { .. } => "F64Store".into(),
        Op::I32Store8 { .. } => "I32Store8".into(),
        Op::I32Store16 { .. } => "I32Store16".into(),
        Op::I64Store8 { .. } => "I64Store8".into(),
        Op::I64Store16 { .. } => "I64Store16".into(),
        Op::I64Store32 { .. } => "I64Store32".into(),
    }
}

fn is_load(op: &Op) -> bool {
    matches!(
        op,
        Op::I32Load { .. }
            | Op::I64Load { .. }
            | Op::F32Load { .. }
            | Op::F64Load { .. }
            | Op::I32Load8S { .. }
            | Op::I32Load8U { .. }
            | Op::I32Load16S { .. }
            | Op::I32Load16U { .. }
            | Op::I64Load8S { .. }
            | Op::I64Load8U { .. }
            | Op::I64Load16S { .. }
            | Op::I64Load16U { .. }
            | Op::I64Load32S { .. }
            | Op::I64Load32U { .. }
    )
}

fn is_store(op: &Op) -> bool {
    matches!(
        op,
        Op::I32Store { .. }
            | Op::I64Store { .. }
            | Op::F32Store { .. }
            | Op::F64Store { .. }
            | Op::I32Store8 { .. }
            | Op::I32Store16 { .. }
            | Op::I64Store8 { .. }
            | Op::I64Store16 { .. }
            | Op::I64Store32 { .. }
    )
}
