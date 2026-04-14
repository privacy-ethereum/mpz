use ir::{ElementItems, ElementKind, Instruction, Module};

use crate::{Memory, VmError, bitset::BitSet, value::Value};

/// Global VM State.
#[derive(Debug)]
pub struct Global {
    /// Linear memory (shared across all calls).
    memory: Option<Memory>,
    /// Which linear memory is symbolic.
    symbolic_memory: BitSet,
    /// Global variables (shared across all calls).
    globals: Vec<Value>,
    /// Which globals are symbolic.
    symbolic_globals: BitSet,
    /// Function table.
    table: Vec<Option<u32>>,
}

impl Global {
    pub fn memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    pub fn memory_mut(&mut self) -> Option<&mut Memory> {
        self.memory.as_mut()
    }

    pub(crate) fn memory_taint(&self) -> &BitSet {
        &self.symbolic_memory
    }

    pub(crate) fn memory_taint_mut(&mut self) -> &mut BitSet {
        &mut self.symbolic_memory
    }

    pub fn globals(&self) -> &[Value] {
        &self.globals
    }

    pub fn globals_mut(&mut self) -> &mut [Value] {
        &mut self.globals
    }

    pub fn is_global_symbolic(&self, idx: u32) -> bool {
        self.symbolic_globals.contains(idx)
    }

    pub fn mark_global_symbolic(&mut self, idx: u32) {
        self.symbolic_globals.insert(idx);
    }

    pub fn mark_global_clear(&mut self, idx: u32) {
        self.symbolic_globals.remove(idx);
    }

    pub fn table(&self) -> &[Option<u32>] {
        &self.table
    }
}

impl Global {
    pub fn new(module: &Module) -> Result<Self, VmError> {
        if module.memories().len() > 1 {
            todo!()
        }

        let mut memory = match module.memories().first() {
            Some(mem) => Some(Memory::new(mem.ty.limits.min, mem.ty.limits.max)?),
            None => None,
        };

        let mut globals: Vec<Value> = Vec::new();

        // Apply data segments to user memory
        for data in module.data() {
            if let ir::DataKind::Active {
                memory_index,
                offset,
            } = &data.kind
            {
                if *memory_index != 0 {
                    return Err(VmError::MemoryNotDefined);
                }

                let offset_val = eval_const_expr(&globals, offset)?;
                let offset_addr = offset_val.as_i32()? as u32;

                let memory = memory.as_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.write_bytes(offset_addr, &data.data)?;
            }
        }

        // Initialize globals (reserve space first)
        globals.resize(module.globals().len(), Value::I32(0));

        // Then evaluate each global's initializer
        for (i, global) in module.globals().iter().enumerate() {
            let value = eval_const_expr(&globals, &global.init)?;
            globals[i] = value;
        }

        // Initialize table
        let mut table = Vec::new();
        if !module.tables().is_empty() {
            let table_size = module.tables()[0].ty.limits.min as usize;
            const MAX_TABLE_SIZE: usize = 1024 * 1024;
            if table_size > MAX_TABLE_SIZE {
                return Err(VmError::Unsupported(format!(
                    "table size {} exceeds limit {}",
                    table_size, MAX_TABLE_SIZE
                )));
            }
            table.resize(table_size, None);

            for elem in module.elements() {
                if let ElementKind::Active {
                    table_index: _,
                    offset,
                } = &elem.kind
                {
                    let offset_val = eval_const_expr(&globals, offset)?;
                    let offset_idx = offset_val.as_i32()? as usize;

                    match &elem.items {
                        ElementItems::Functions(func_indices) => {
                            for (i, func_idx) in func_indices.iter().enumerate() {
                                let table_idx = offset_idx + i;
                                if table_idx >= table.len() {
                                    return Err(crate::Trap::UndefinedElement.into());
                                }
                                table[table_idx] = Some(*func_idx);
                            }
                        }
                        ElementItems::Expressions(_ref_type, exprs) => {
                            for (i, expr) in exprs.iter().enumerate() {
                                let table_idx = offset_idx + i;
                                if table_idx >= table.len() {
                                    return Err(crate::Trap::UndefinedElement.into());
                                }
                                let func_idx = eval_elem_expr(expr)?;
                                table[table_idx] = func_idx;
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            memory,
            symbolic_memory: BitSet::default(),
            globals,
            symbolic_globals: BitSet::default(),
            table,
        })
    }
}

fn eval_const_expr(globals: &[Value], expr: &[Instruction]) -> Result<Value, VmError> {
    let mut stack: Vec<i32> = Vec::new();

    for instr in expr {
        match instr {
            Instruction::I32Const { val, .. } => stack.push(*val),
            Instruction::I64Const { val, .. } => {
                stack.push(*val as i32);
            }
            Instruction::GlobalGet { global_idx, .. } => {
                let val = globals
                    .get(*global_idx as usize)
                    .ok_or(VmError::UndefinedGlobal(*global_idx))?
                    .as_i32()?;
                stack.push(val);
            }
            _ => {}
        }
    }

    Ok(Value::from(stack.pop().unwrap_or(0)))
}

fn eval_elem_expr(expr: &[Instruction]) -> Result<Option<u32>, VmError> {
    for instr in expr {
        match instr {
            Instruction::RefFunc { func_idx, .. } => return Ok(Some(*func_idx)),
            Instruction::RefNull { .. } => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}
