use mpz_vm_ir::{ConstExpr, ElementItems, ElementKind, Instruction, Module};

use crate::{Error, Memory, Trap, Visibility, taint::Taints, value::Value};

/// State shared across all calls executing against a single [`Module`].
///
/// A `Global` holds the linear [`Memory`], the global variables, and the
/// function table defined by a module, and tracks the [`Visibility`] of memory
/// and global values.
#[derive(Debug)]
pub struct Global {
    memory: Option<Memory>,
    memory_taints: Taints,
    globals: Vec<Value>,
    global_taints: Taints,
    table: Vec<Option<u32>>,
}

impl Global {
    /// Returns a reference to the linear memory, or `None` if the module
    /// defines no memory.
    pub fn memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    /// Returns a mutable reference to the linear memory, or `None` if the
    /// module defines no memory.
    pub fn memory_mut(&mut self) -> Option<&mut Memory> {
        self.memory.as_mut()
    }

    pub(crate) fn memory_taints(&self) -> &Taints {
        &self.memory_taints
    }

    pub(crate) fn memory_taints_mut(&mut self) -> &mut Taints {
        &mut self.memory_taints
    }

    pub(crate) fn globals(&self) -> &[Value] {
        &self.globals
    }

    pub(crate) fn globals_mut(&mut self) -> &mut [Value] {
        &mut self.globals
    }

    pub(crate) fn global_taints(&self) -> &Taints {
        &self.global_taints
    }

    pub(crate) fn global_taints_mut(&mut self) -> &mut Taints {
        &mut self.global_taints
    }

    pub(crate) fn table(&self) -> &[Option<u32>] {
        &self.table
    }

    /// Returns `true` if any byte in the range `[addr, addr + len)` of linear
    /// memory is tainted as symbolic.
    pub fn memory_tainted(&self, addr: u32, len: usize) -> bool {
        self.memory_taints.any_symbolic(addr, len)
    }

    /// Sets the [`Visibility`] of the `len` bytes of linear memory starting at
    /// `addr`.
    pub fn set_memory_visibility(&mut self, addr: u32, len: usize, visibility: Visibility) {
        self.memory_taints.set_range(addr, len, visibility.into());
    }
}

impl Global {
    /// Constructs the global state for `module`.
    ///
    /// Allocates the module's linear memory, applies its active data segments,
    /// initializes its global variables, and populates its function table from
    /// the module's active element segments.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unimplemented`] if the requested function table exceeds
    /// the supported size limit, [`Error::MemoryNotDefined`] if a data
    /// segment targets a memory that does not exist, [`Error::UndefinedGlobal`]
    /// if a constant initializer references an undefined global, and
    /// [`Error::Trap`] if applying a data or element segment falls outside the
    /// bounds of memory or the table.
    ///
    /// # Panics
    ///
    /// Panics if the module defines more than one memory.
    pub fn new(module: &Module) -> Result<Self, Error> {
        if module.memories().len() > 1 {
            todo!()
        }

        let mut memory = match module.memories().first() {
            Some(mem) => Some(Memory::new(mem.ty.limits.min, mem.ty.limits.max)?),
            None => None,
        };

        let mut globals: Vec<Value> = Vec::new();

        for data in module.data() {
            if let mpz_vm_ir::DataKind::Active {
                memory_index,
                offset,
            } = &data.kind
            {
                if *memory_index != 0 {
                    return Err(Error::MemoryNotDefined);
                }

                let offset_val = eval_const_expr(&globals, offset)?;
                let offset_addr = offset_val.as_i32()? as u32;

                let memory = memory.as_mut().ok_or(Error::MemoryNotDefined)?;
                memory
                    .write_bytes(offset_addr, &data.data)
                    .map_err(Error::Trap)?;
            }
        }

        // Size the vector before evaluating initializers so that an
        // initializer referencing an earlier global resolves against a
        // populated slot.
        globals.resize(module.globals().len(), Value::I32(0));

        for (i, global) in module.globals().iter().enumerate() {
            let value = eval_const_expr(&globals, &global.init)?;
            globals[i] = value;
        }

        let mut table = Vec::new();
        if !module.tables().is_empty() {
            let table_size = module.tables()[0].ty.limits.min as usize;
            const MAX_TABLE_SIZE: usize = 1024 * 1024;
            if table_size > MAX_TABLE_SIZE {
                return Err(Error::Unimplemented("table size exceeds supported limit"));
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
                                    return Err(Error::Trap(Trap::UndefinedElement));
                                }
                                table[table_idx] = Some(*func_idx);
                            }
                        }
                        ElementItems::Expressions(_ref_type, exprs) => {
                            for (i, expr) in exprs.iter().enumerate() {
                                let table_idx = offset_idx + i;
                                if table_idx >= table.len() {
                                    return Err(Error::Trap(Trap::UndefinedElement));
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
            memory_taints: Taints::new(),
            globals,
            global_taints: Taints::new(),
            table,
        })
    }
}

fn eval_const_expr(globals: &[Value], expr: &ConstExpr) -> Result<Value, Error> {
    match expr {
        ConstExpr::I32(v) => Ok(Value::I32(*v)),
        ConstExpr::I64(v) => Ok(Value::I64(*v)),
        ConstExpr::F32(bits) => Ok(Value::F32(f32::from_bits(*bits))),
        ConstExpr::F64(bits) => Ok(Value::F64(f64::from_bits(*bits))),
        ConstExpr::GlobalGet(global_idx) => globals
            .get(*global_idx as usize)
            .copied()
            .ok_or(Error::UndefinedGlobal(*global_idx)),
        ConstExpr::RefFunc(func_idx) => Ok(Value::I32(*func_idx as i32)),
        ConstExpr::RefNull(_) => Ok(Value::I32(0)),
    }
}

fn eval_elem_expr(expr: &[Instruction]) -> Result<Option<u32>, Error> {
    for instr in expr {
        match instr {
            Instruction::RefFunc { func_idx, .. } => return Ok(Some(*func_idx)),
            Instruction::RefNull { .. } => return Ok(None),
            _ => {}
        }
    }
    Ok(None)
}
