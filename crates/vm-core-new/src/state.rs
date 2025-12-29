use ir::{ElementItems, ElementKind, Instruction, Module};

use crate::{Memory, VmError, value::IValue};

/// VM State.
#[derive(Debug)]
pub struct State {
    /// Linear memory (shared across all calls).
    memory: Option<Memory>,
    /// Global variables (shared across all calls).
    globals: Vec<IValue>,
    /// Function table.
    table: Vec<Option<u32>>,
}

impl State {
    /// Get a reference to memory.
    pub fn memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    /// Get a mutable reference to memory.
    pub fn memory_mut(&mut self) -> Option<&mut Memory> {
        self.memory.as_mut()
    }

    /// Get a reference to globals.
    pub fn globals(&self) -> &[IValue] {
        &self.globals
    }

    /// Get a mutable reference to globals.
    pub fn globals_mut(&mut self) -> &mut [IValue] {
        &mut self.globals
    }

    /// Get a reference to the function table.
    pub fn table(&self) -> &[Option<u32>] {
        &self.table
    }
}

impl State {
    /// Create a new VM state.
    pub fn new(module: &Module) -> Result<Self, VmError> {
        if module.memories().len() > 1 {
            todo!()
        }

        let mut memory = match module.memories().first() {
            Some(mem) => Some(Memory::new(mem.ty.limits.min, mem.ty.limits.max)?),
            None => None,
        };

        let mut globals = Vec::new();

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

                // Evaluate offset expression (should be a constant)
                let offset_val = eval_const_expr(&globals, offset)?;
                let offset_addr = offset_val.as_i32()?.as_clear()? as u32;

                let memory = memory.as_mut().ok_or(VmError::MemoryNotDefined)?;
                memory.write_clear(offset_addr, &data.data)?;
            }
        }

        // Initialize globals (reserve space first)
        globals.resize(module.globals().len(), IValue::from(0));

        // Then evaluate each global's initializer
        for (i, global) in module.globals().iter().enumerate() {
            let value = eval_const_expr(&globals, &global.init)?;
            globals[i] = value;
        }

        // Initialize table
        let mut table = Vec::new();
        if !module.tables().is_empty() {
            let table_size = module.tables()[0].ty.limits.min as usize;
            // Limit table size to prevent OOM
            const MAX_TABLE_SIZE: usize = 1024 * 1024; // 1M entries
            if table_size > MAX_TABLE_SIZE {
                return Err(VmError::Unsupported(format!(
                    "table size {} exceeds limit {}",
                    table_size, MAX_TABLE_SIZE
                )));
            }
            table.resize(table_size, None);

            // Apply element segments
            for elem in module.elements() {
                if let ElementKind::Active {
                    table_index: _,
                    offset,
                } = &elem.kind
                {
                    let offset_val = eval_const_expr(&globals, offset)?;
                    let offset_idx = offset_val.as_i32()?.as_clear()? as usize;

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
                                // Evaluate expression to get function reference
                                let func_idx = eval_elem_expr(expr)?;
                                table[table_idx] = func_idx;
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            globals,
            memory,
            table,
        })
    }
}

/// Evaluate a constant expression (used for globals and data offsets).
fn eval_const_expr(globals: &[IValue], expr: &[Instruction]) -> Result<IValue, VmError> {
    // Stack-based evaluation for constant expressions (supports extended const
    // exprs)
    let mut stack: Vec<i32> = Vec::new();

    for instr in expr {
        match instr {
            Instruction::I32Const(value) => stack.push(*value),
            Instruction::I64Const(value) => {
                // For offset calculations, truncate to i32
                stack.push(*value as i32);
            }
            Instruction::GlobalGet(global_idx) => {
                let val = globals
                    .get(*global_idx as usize)
                    .ok_or(VmError::UndefinedGlobal(*global_idx))?
                    .as_i32()?
                    .as_clear()?;
                stack.push(val);
            }
            Instruction::Arith(arith) => {
                use ir::InstructionArith::*;
                match arith {
                    I32Add => {
                        let b = stack.pop().unwrap_or(0);
                        let a = stack.pop().unwrap_or(0);
                        stack.push(a.wrapping_add(b));
                    }
                    I32Sub => {
                        let b = stack.pop().unwrap_or(0);
                        let a = stack.pop().unwrap_or(0);
                        stack.push(a.wrapping_sub(b));
                    }
                    I32Mul => {
                        let b = stack.pop().unwrap_or(0);
                        let a = stack.pop().unwrap_or(0);
                        stack.push(a.wrapping_mul(b));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(IValue::from(stack.pop().unwrap_or(0)))
}

/// Evaluate an element expression (returns function index or None for
/// null).
fn eval_elem_expr(expr: &[Instruction]) -> Result<Option<u32>, VmError> {
    for instr in expr {
        match instr {
            Instruction::RefFunc(func_idx) => return Ok(Some(*func_idx)),
            Instruction::RefNull(_) => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}
