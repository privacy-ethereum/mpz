use wasmparser::{
    BinaryReader, BlockType as WasmBlockType, CompositeInnerType, Data as WasmData,
    DataKind as WasmDataKind, Element as WasmElement, ElementItems as WasmElementItems,
    ElementKind as WasmElementKind, Export as WasmExport, ExternalKind, Global as WasmGlobal,
    GlobalType as WasmGlobalType, HeapType, MemoryType as WasmMemoryType, Operator, Parser,
    Payload, RefType as WasmRefType, TableType as WasmTableType, TypeRef, ValType as WasmValType,
};

use crate::{
    BasicBlock, BinaryArith, BinaryOp, BlockId, BranchRegion, Data, DataKind, Element,
    ElementItems, ElementKind, Error, Export, ExportKind, FuncType, Function, FunctionBody, Global,
    GlobalType, Import, ImportType, ImportedFunction, Instruction, InstructionArith, Limits, Local,
    LocalFunction, MemArg, Memory, MemoryType, Module, RefType, Reg, Result, Table, TableType,
    Terminator, UnaryArith, UnaryOp, ValType,
};

pub fn parse_module(bytes: &[u8]) -> Result<Module> {
    let parser = Parser::new(0);

    let mut types: Vec<FuncType> = Vec::new();
    let mut functions: Vec<Function> = Vec::new();
    let mut imports: Vec<Import> = Vec::new();
    let mut tables: Vec<Table> = Vec::new();
    let mut memories: Vec<Memory> = Vec::new();
    let mut globals: Vec<Global> = Vec::new();
    let mut exports: Vec<Export> = Vec::new();
    let mut start: Option<u32> = None;
    let mut elements: Vec<Element> = Vec::new();
    let mut data_count: Option<u32> = None;
    let mut data: Vec<Data> = Vec::new();
    let mut function_names = std::collections::HashMap::new();

    // Temporary storage for function imports (to resolve types later)
    let mut func_imports: Vec<(String, String, u32)> = Vec::new();
    let mut num_imported_tables = 0usize;
    let mut function_type_indices = Vec::new();
    let mut function_bodies = Vec::new();

    for payload in parser.parse_all(bytes) {
        let payload = payload?;
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != wasmparser::Encoding::Module {
                    return Err(Error::UnsupportedFeature(
                        "only WebAssembly modules are supported".to_string(),
                    ));
                }
            }
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group?;
                    for ty in rec_group.into_types() {
                        if let CompositeInnerType::Func(func_ty) = ty.composite_type.inner {
                            types.push(parse_func_type(&func_ty)?);
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    match import.ty {
                        TypeRef::Func(type_idx) => {
                            func_imports.push((
                                import.module.to_string(),
                                import.name.to_string(),
                                type_idx,
                            ));
                        }
                        TypeRef::Table(table_ty) => {
                            num_imported_tables += 1;
                            imports.push(Import {
                                module: import.module.to_string(),
                                name: import.name.to_string(),
                                ty: ImportType::Table(parse_table_type(&table_ty)?),
                            });
                        }
                        TypeRef::Memory(memory_ty) => {
                            imports.push(Import {
                                module: import.module.to_string(),
                                name: import.name.to_string(),
                                ty: ImportType::Memory(parse_memory_type(&memory_ty)?),
                            });
                        }
                        TypeRef::Global(global_ty) => {
                            imports.push(Import {
                                module: import.module.to_string(),
                                name: import.name.to_string(),
                                ty: ImportType::Global(parse_global_type(&global_ty)?),
                            });
                        }
                        _ => {
                            return Err(Error::UnsupportedFeature(
                                "unsupported import type".to_string(),
                            ));
                        }
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for func_type_idx in reader {
                    function_type_indices.push(func_type_idx?);
                }
            }
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table?;
                    tables.push(parse_table(&table.ty)?);
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    memories.push(parse_memory(&memory?)?);
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    globals.push(parse_global(&global?)?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    exports.push(parse_export(&export?)?);
                }
            }
            Payload::StartSection { func: func_idx, .. } => {
                start = Some(func_idx);
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    elements.push(parse_element(&element?)?);
                }
            }
            Payload::DataCountSection { count, .. } => {
                data_count = Some(count);
            }
            Payload::DataSection(reader) => {
                for d in reader {
                    data.push(parse_data(&d?)?);
                }
            }
            Payload::CodeSectionEntry(body) => {
                function_bodies.push(body);
            }
            Payload::CustomSection(reader) => {
                if reader.name() == "name" {
                    let binary_reader = BinaryReader::new(reader.data(), reader.data_offset());
                    let name_reader = wasmparser::NameSectionReader::new(binary_reader);
                    for name in name_reader.into_iter().flatten() {
                        if let wasmparser::Name::Function(map) = name {
                            for naming in map.into_iter().flatten() {
                                function_names.insert(naming.index, naming.name.to_string());
                            }
                        }
                    }
                }
            }
            Payload::CodeSectionStart { .. } => {
                // Handled by CodeSectionEntry
            }
            Payload::ModuleSection { .. } => {
                return Err(Error::UnsupportedFeature(
                    "nested modules not supported".to_string(),
                ));
            }
            Payload::ComponentSection { .. } => {
                return Err(Error::UnsupportedFeature(
                    "components not supported".to_string(),
                ));
            }
            Payload::UnknownSection { .. } => {
                // Skip unknown sections
            }
            Payload::End(_) => {}
            other => {
                return Err(Error::UnsupportedFeature(format!(
                    "unsupported payload type: {:?}",
                    other
                )));
            }
        }
    }

    // Build imported functions first (imports come before local functions in
    // indexing)
    let num_imported_funcs = func_imports.len();
    for (module_name, name, type_idx) in &func_imports {
        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::UnsupportedFeature("invalid type index".to_string()))?;
        functions.push(Function::Import(ImportedFunction::new(
            module_name.clone(),
            name.clone(),
            func_type,
        )));
    }

    // Build function type lookup for translation (imports + local functions)
    let mut func_type_lookup: Vec<FuncType> =
        Vec::with_capacity(func_imports.len() + function_type_indices.len());
    for (_, _, type_idx) in &func_imports {
        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::Validation("unknown type".to_string()))?;
        func_type_lookup.push(func_type);
    }
    for type_idx in &function_type_indices {
        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::Validation("unknown type".to_string()))?;
        func_type_lookup.push(func_type);
    }

    // Build local functions
    for (type_idx, body) in function_type_indices.iter().zip(function_bodies.iter()) {
        let mut locals = Vec::new();
        let mut reader = body.get_binary_reader();

        for _ in 0..reader.read_var_u32()? {
            let count = reader.read_var_u32()?;
            let ty = parse_val_type(reader.read()?)?;
            locals.push(Local { count, ty });
        }

        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::Validation("invalid type index".to_string()))?;

        // Calculate number of locals (params + local variables)
        let num_params = func_type.params.len() as u32;
        let num_local_vars: u32 = locals.iter().map(|l| l.count).sum();
        let num_locals = num_params + num_local_vars;

        let (num_regs, body) = translate_to_registers(
            &mut reader,
            num_locals,
            &func_type,
            &func_type_lookup,
            &types,
        )?;

        functions.push(Function::Local(LocalFunction::new(
            func_type,
            locals.into(),
            num_regs,
            body,
        )));
    }

    // Validate data count if present
    if let Some(count) = data_count {
        if data.len() != count as usize {
            return Err(Error::Validation(format!(
                "data count mismatch: expected {}, got {}",
                count,
                data.len()
            )));
        }
    }

    Ok(Module {
        types,
        functions,
        num_imported_funcs,
        num_imported_tables,
        tables,
        memories,
        globals,
        exports,
        function_names,
        start,
        elements,
        data,
    })
}

fn parse_func_type(ty: &wasmparser::FuncType) -> Result<FuncType> {
    let params = ty
        .params()
        .iter()
        .map(|p| parse_val_type(*p))
        .collect::<Result<Vec<_>>>()?;
    let results = ty
        .results()
        .iter()
        .map(|r| parse_val_type(*r))
        .collect::<Result<Vec<_>>>()?;
    Ok(FuncType { params, results })
}

fn parse_val_type(ty: WasmValType) -> Result<ValType> {
    match ty {
        WasmValType::I32 => Ok(ValType::I32),
        WasmValType::I64 => Ok(ValType::I64),
        WasmValType::F32 => Ok(ValType::F32),
        WasmValType::F64 => Ok(ValType::F64),
        _ => Err(Error::UnsupportedFeature(format!(
            "unsupported value type: {:?}",
            ty
        ))),
    }
}

fn parse_ref_type(ty: WasmRefType) -> Result<RefType> {
    if ty.is_func_ref() {
        Ok(RefType::FuncRef)
    } else if ty.is_extern_ref() {
        Ok(RefType::ExternRef)
    } else {
        Err(Error::UnsupportedFeature(format!(
            "unsupported reference type: {:?}",
            ty
        )))
    }
}

fn parse_table(table_ty: &WasmTableType) -> Result<Table> {
    Ok(Table {
        ty: parse_table_type(table_ty)?,
    })
}

fn parse_table_type(ty: &WasmTableType) -> Result<TableType> {
    let element_type = parse_ref_type(ty.element_type)?;
    let limits = Limits {
        min: ty.initial,
        max: ty.maximum,
    };
    Ok(TableType {
        element_type,
        limits,
    })
}

fn parse_memory(memory_ty: &WasmMemoryType) -> Result<Memory> {
    Ok(Memory {
        ty: parse_memory_type(memory_ty)?,
    })
}

fn parse_memory_type(ty: &WasmMemoryType) -> Result<MemoryType> {
    Ok(MemoryType {
        limits: Limits {
            min: ty.initial,
            max: ty.maximum,
        },
        shared: ty.shared,
    })
}

fn parse_global(global: &WasmGlobal) -> Result<Global> {
    let mut reader = global.init_expr.get_binary_reader();
    let init = parse_const_expr(&mut reader)?;

    Ok(Global {
        ty: parse_global_type(&global.ty)?,
        init,
    })
}

fn parse_global_type(ty: &WasmGlobalType) -> Result<GlobalType> {
    Ok(GlobalType {
        val_type: parse_val_type(ty.content_type)?,
        mutable: ty.mutable,
    })
}

fn parse_export(export: &WasmExport) -> Result<Export> {
    let kind = match export.kind {
        ExternalKind::Func => ExportKind::Func(export.index),
        ExternalKind::Table => ExportKind::Table(export.index),
        ExternalKind::Memory => ExportKind::Memory(export.index),
        ExternalKind::Global => ExportKind::Global(export.index),
        _ => {
            return Err(Error::UnsupportedFeature(
                "unsupported export kind".to_string(),
            ));
        }
    };

    Ok(Export {
        name: export.name.to_string(),
        kind,
    })
}

fn parse_element(element: &WasmElement) -> Result<Element> {
    let kind = match &element.kind {
        WasmElementKind::Passive => ElementKind::Passive,
        WasmElementKind::Active {
            table_index,
            offset_expr,
        } => {
            let mut reader = offset_expr.get_binary_reader();
            let offset = parse_const_expr(&mut reader)?;
            ElementKind::Active {
                table_index: table_index.unwrap_or(0),
                offset,
            }
        }
        WasmElementKind::Declared => ElementKind::Declared,
    };

    let items = match &element.items {
        WasmElementItems::Functions(reader) => {
            let funcs = reader
                .clone()
                .into_iter()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ElementItems::Functions(funcs)
        }
        WasmElementItems::Expressions(ref_ty, reader) => {
            let ref_type = parse_ref_type(*ref_ty)?;
            let mut exprs = Vec::new();
            for expr in reader.clone() {
                let mut expr_reader = expr?.get_binary_reader();
                exprs.push(parse_const_expr(&mut expr_reader)?);
            }
            ElementItems::Expressions(ref_type, exprs)
        }
    };

    Ok(Element { kind, items })
}

fn parse_data(data: &WasmData) -> Result<Data> {
    let kind = match &data.kind {
        WasmDataKind::Passive => DataKind::Passive,
        WasmDataKind::Active {
            memory_index,
            offset_expr,
        } => {
            let mut reader = offset_expr.get_binary_reader();
            let offset = parse_const_expr(&mut reader)?;
            DataKind::Active {
                memory_index: *memory_index,
                offset,
            }
        }
    };

    Ok(Data {
        kind,
        data: data.data.to_vec(),
    })
}

/// Parse simple constant expressions (for globals, element offsets, etc).
/// These use register 0 as a dummy destination since they're just evaluated
/// once.
fn parse_const_expr(reader: &mut BinaryReader) -> Result<Vec<Instruction>> {
    let mut instrs = Vec::new();
    let dummy_reg: Reg = 0;

    while !reader.eof() {
        let op = reader.read_operator()?;
        use Operator::*;
        let instr = match &op {
            I32Const { value } => Instruction::I32Const {
                dst: dummy_reg,
                val: *value,
            },
            I64Const { value } => Instruction::I64Const {
                dst: dummy_reg,
                val: *value,
            },
            F32Const { value } => Instruction::F32Const {
                dst: dummy_reg,
                val: value.bits(),
            },
            F64Const { value } => Instruction::F64Const {
                dst: dummy_reg,
                val: value.bits(),
            },
            GlobalGet { global_index } => Instruction::GlobalGet {
                dst: dummy_reg,
                global_idx: *global_index,
            },
            RefNull { hty } => {
                let ref_type = match hty {
                    HeapType::Concrete(_) => {
                        return Err(Error::UnsupportedFeature(format!(
                            "concrete heap types not supported: {:?}",
                            hty
                        )));
                    }
                    HeapType::Abstract { shared: _, ty } => match ty {
                        wasmparser::AbstractHeapType::Func => RefType::FuncRef,
                        wasmparser::AbstractHeapType::Extern => RefType::ExternRef,
                        _ => {
                            return Err(Error::UnsupportedFeature(format!(
                                "unsupported abstract heap type: {:?}",
                                ty
                            )));
                        }
                    },
                };
                Instruction::RefNull {
                    dst: dummy_reg,
                    ty: ref_type,
                }
            }
            RefFunc { function_index } => Instruction::RefFunc {
                dst: dummy_reg,
                func_idx: *function_index,
            },
            End => continue,
            _ => {
                return Err(Error::UnsupportedFeature(format!(
                    "unsupported const expr instruction: {:?}",
                    op
                )));
            }
        };
        instrs.push(instr);
    }

    Ok(instrs)
}

/// Tracks a control flow scope (block/loop/if) for CFG construction.
#[derive(Clone)]
struct Scope {
    /// Stack height when entering this scope.
    stack_height: usize,
    /// Whether we were unreachable when entering.
    was_unreachable: bool,
    /// Result arity of this block.
    result_arity: usize,
    /// Whether this is a loop.
    is_loop: bool,
    /// Whether this is an if block.
    is_if: bool,
    /// Pre-allocated result register for blocks with results.
    block_result_reg: Option<Reg>,
    /// Whether the then branch was reachable (set at Else).
    then_was_reachable: bool,
    /// Continuation block (code after End). For loops, also used at End.
    continuation: BlockId,
    /// For if: the else block (or join if no else).
    else_block: Option<BlockId>,
}

/// Translator from stack-based WASM to CFG-based register instructions.
struct Translator {
    /// Virtual stack: maps stack position to register ID.
    reg_stack: Vec<Reg>,
    /// Next available register (starts after locals).
    next_reg: Reg,
    /// Number of local registers (0..num_locals are reserved).
    num_locals: Reg,
    /// Free list of reusable registers.
    free_regs: Vec<Reg>,
    /// Whether we're in unreachable code.
    unreachable: bool,
    /// Stack of control flow scopes.
    scopes: Vec<Scope>,
    /// All finished basic blocks.
    blocks: Vec<BasicBlock>,
    /// Instructions for the current (in-progress) block.
    current_body: Vec<Instruction>,
    /// BlockId of the current block being built.
    current_block: BlockId,
    /// Next block ID to allocate.
    next_block_id: u32,
}

impl Translator {
    fn new(num_locals: u32) -> Self {
        Self {
            reg_stack: Vec::new(),
            next_reg: num_locals,
            num_locals: num_locals,
            free_regs: Vec::new(),
            unreachable: false,
            scopes: Vec::new(),
            blocks: Vec::new(),
            current_body: Vec::new(),
            current_block: BlockId(0),
            next_block_id: 1,
        }
    }

    /// Allocate a new BlockId.
    fn alloc_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        id
    }

    /// Finish the current block with the given terminator.
    /// Start a new block and return its BlockId.
    fn finish_block(&mut self, terminator: Terminator) -> BlockId {
        let body = std::mem::take(&mut self.current_body);
        let block = BasicBlock { body, terminator };
        // Ensure blocks vec is large enough
        let idx = self.current_block.index();
        if idx >= self.blocks.len() {
            self.blocks.resize(
                idx + 1,
                BasicBlock {
                    body: Vec::new(),
                    terminator: Terminator::Unreachable,
                },
            );
        }
        self.blocks[idx] = block;

        let new_block = self.alloc_block();
        self.current_block = new_block;
        new_block
    }

    /// Finish the current block with the given terminator and switch to the
    /// specified existing block (don't allocate a new one).
    fn finish_block_and_switch_to(&mut self, terminator: Terminator, target: BlockId) {
        let body = std::mem::take(&mut self.current_body);
        let block = BasicBlock { body, terminator };
        let idx = self.current_block.index();
        if idx >= self.blocks.len() {
            self.blocks.resize(
                idx + 1,
                BasicBlock {
                    body: Vec::new(),
                    terminator: Terminator::Unreachable,
                },
            );
        }
        self.blocks[idx] = block;
        self.current_block = target;
    }

    /// Allocate a new register and push it on the virtual stack.
    fn push(&mut self) -> Reg {
        let r = if let Some(r) = self.free_regs.pop() {
            r
        } else {
            let r = self.next_reg;
            self.next_reg += 1;
            r
        };
        if !self.unreachable {
            self.reg_stack.push(r);
        }
        r
    }

    /// Pop a register from the virtual stack.
    fn pop(&mut self) -> Result<Reg> {
        if self.unreachable {
            return Ok(0);
        }
        let r = self
            .reg_stack
            .pop()
            .ok_or_else(|| Error::Validation("stack underflow".to_string()))?;
        // Reclaim non-local, non-aliased registers.
        if r >= self.num_locals {
            self.free_regs.push(r);
        }
        Ok(r)
    }

    /// Peek at the top of the virtual stack.
    fn peek(&self) -> Result<Reg> {
        if self.unreachable {
            return Ok(0);
        }
        self.reg_stack
            .last()
            .copied()
            .ok_or_else(|| Error::Validation("stack underflow".to_string()))
    }

    /// Materialize any aliased references to a local register on the stack.
    /// Called before writing to a local so that existing stack references
    /// to the old value get their own registers.
    fn materialize_local(&mut self, local_reg: Reg) {
        for entry in self.reg_stack.iter_mut() {
            if *entry == local_reg {
                let new_reg = if let Some(r) = self.free_regs.pop() {
                    r
                } else {
                    let r = self.next_reg;
                    self.next_reg += 1;
                    r
                };
                self.current_body.push(Instruction::Copy {
                    dst: new_reg,
                    src: local_reg,
                });
                *entry = new_reg;
            }
        }
    }

    /// Emit an instruction to the current block.
    fn emit(&mut self, instr: Instruction) {
        self.current_body.push(instr);
    }

    /// Get the branch arity for a given depth.
    fn branch_arity(&self, depth: u32) -> usize {
        let idx = self.scopes.len().saturating_sub(1 + depth as usize);
        if let Some(scope) = self.scopes.get(idx) {
            if scope.is_loop { 0 } else { scope.result_arity }
        } else {
            0
        }
    }

    /// Get the result register for the target block at given depth.
    fn branch_result_reg(&self, depth: u32) -> Option<Reg> {
        let idx = self.scopes.len().saturating_sub(1 + depth as usize);
        self.scopes.get(idx).and_then(|s| s.block_result_reg)
    }

    /// Mark as unreachable.
    fn set_unreachable(&mut self) {
        self.unreachable = true;
    }

    /// Translate a unary arithmetic op.
    fn unary_op(&mut self, op: UnaryOp) -> Result<()> {
        let src = self.pop()?;
        let dst = self.push();
        self.emit(Instruction::Arith(InstructionArith::Unary(UnaryArith {
            op,
            dst,
            src,
        })));
        Ok(())
    }

    /// Translate a binary arithmetic op.
    fn binary_op(&mut self, op: BinaryOp) -> Result<()> {
        let rhs = self.pop()?;
        let lhs = self.pop()?;
        let dst = self.push();
        self.emit(Instruction::Arith(InstructionArith::Binary(BinaryArith {
            op,
            dst,
            lhs,
            rhs,
        })));
        Ok(())
    }
}

fn translate_to_registers(
    reader: &mut BinaryReader,
    num_locals: u32,
    func_type: &FuncType,
    all_func_types: &[FuncType],
    all_types: &[FuncType],
) -> Result<(u32, FunctionBody)> {
    let mut t = Translator::new(num_locals);

    while !reader.eof() {
        let op = reader.read_operator()?;
        translate_operator(&mut t, &op, func_type, all_func_types, all_types)?;
    }

    // Emit implicit return if reachable
    if !t.unreachable {
        let num_results = func_type.results.len();
        let terminator = if num_results > 0 && t.reg_stack.len() >= num_results {
            let values: Vec<Reg> = t
                .reg_stack
                .iter()
                .rev()
                .take(num_results)
                .rev()
                .copied()
                .collect();
            Terminator::Return { values }
        } else {
            Terminator::Return { values: vec![] }
        };
        // Finish the last block
        t.finish_block(terminator);
    } else {
        // Even unreachable code needs a terminated block
        t.finish_block(Terminator::Unreachable);
    }

    let mut body = FunctionBody {
        entry: BlockId(0),
        blocks: t.blocks,
    };

    compute_branch_regions(&mut body);

    Ok((t.next_reg, body))
}

fn translate_operator(
    t: &mut Translator,
    op: &Operator,
    func_type: &FuncType,
    all_func_types: &[FuncType],
    all_types: &[FuncType],
) -> Result<()> {
    use Operator::*;

    match op {
        // === Control Flow ===
        Unreachable => {
            t.finish_block(Terminator::Unreachable);
            t.set_unreachable();
        }
        Nop => t.emit(Instruction::Nop),
        Block { blockty } => {
            let arity = block_type_result_arity(blockty);
            let continuation = t.alloc_block();

            let block_result_reg = if arity > 0 {
                let reg = t.next_reg;
                t.next_reg += 1;
                Some(reg)
            } else {
                None
            };

            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: false,
                is_if: false,
                block_result_reg,
                then_was_reachable: false,
                continuation,
                else_block: None,
            });
            // Continue emitting into current block (block body)
        }
        Loop { blockty } => {
            let arity = block_type_result_arity(blockty);
            let header = t.alloc_block();
            let continuation = t.alloc_block();

            // Current block jumps to header
            if !t.unreachable {
                t.finish_block_and_switch_to(Terminator::Jump { target: header }, header);
            } else {
                t.current_block = header;
            }

            // For loops, br 0 goes back to header, not continuation.
            // We don't allocate a result reg for loops since br to loop takes 0 values.
            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: true,
                is_if: false,
                block_result_reg: None,
                then_was_reachable: false,
                continuation,
                // Store header as else_block field (reuse for loop header)
                else_block: Some(header),
            });
        }
        If { blockty } => {
            let cond = t.pop()?;
            let arity = block_type_result_arity(blockty);
            let then_block = t.alloc_block();
            let else_block = t.alloc_block();
            let join_block = t.alloc_block();

            let block_result_reg = if arity > 0 {
                let reg = t.next_reg;
                t.next_reg += 1;
                Some(reg)
            } else {
                None
            };

            // Current block ends with BrCond
            if !t.unreachable {
                t.finish_block_and_switch_to(
                    Terminator::BrCond {
                        cond,
                        then_target: then_block,
                        else_target: else_block,
                        join: join_block,
                        region: BranchRegion::default(),
                    },
                    then_block,
                );
            } else {
                t.current_block = then_block;
            }

            t.scopes.push(Scope {
                stack_height: t.reg_stack.len(),
                was_unreachable: t.unreachable,
                result_arity: arity,
                is_loop: false,
                is_if: true,
                block_result_reg,
                then_was_reachable: false,
                continuation: join_block,
                else_block: Some(else_block),
            });
        }
        Else => {
            // Finish then-branch, switch to else-branch
            let scope = t.scopes.last().expect("scope should exist for Else");
            let join_block = scope.continuation;
            let else_block = scope.else_block.expect("if scope should have else_block");
            let block_result_reg = scope.block_result_reg;
            let stack_height = scope.stack_height;
            let was_unreachable = scope.was_unreachable;
            let then_was_reachable = !t.unreachable;

            // Copy then-branch result to unified register if needed
            if let Some(result_reg) = block_result_reg {
                if then_was_reachable {
                    if let Some(&src_reg) = t.reg_stack.last() {
                        if src_reg != result_reg {
                            t.emit(Instruction::Copy {
                                dst: result_reg,
                                src: src_reg,
                            });
                        }
                    }
                }
            }

            // Finish then block with jump to join
            if then_was_reachable {
                t.finish_block_and_switch_to(Terminator::Jump { target: join_block }, else_block);
            } else {
                // Then was unreachable, still need to finalize its block
                t.finish_block_and_switch_to(Terminator::Unreachable, else_block);
            }

            // Update scope
            if let Some(scope) = t.scopes.last_mut() {
                scope.then_was_reachable = then_was_reachable;
            }

            // Restore stack for else branch
            t.reg_stack.truncate(stack_height);
            t.unreachable = was_unreachable;
        }
        End => {
            if let Some(scope) = t.scopes.pop() {
                let join_block = scope.continuation;

                if scope.is_loop {
                    // Loop End: fall through to continuation
                    // The loop header is stored in else_block
                    if !t.unreachable {
                        t.finish_block_and_switch_to(
                            Terminator::Jump { target: join_block },
                            join_block,
                        );
                    } else {
                        t.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                    }

                    // Restore stack
                    if t.unreachable {
                        t.reg_stack.truncate(scope.stack_height);
                    } else {
                        let target_height = scope.stack_height + scope.result_arity;
                        if t.reg_stack.len() >= target_height {
                            t.reg_stack.truncate(target_height);
                        }
                    }
                    t.unreachable = scope.was_unreachable;
                } else if scope.is_if {
                    // If End (could be after then or else)
                    if let Some(result_reg) = scope.block_result_reg {
                        // Copy fall-through result to unified register
                        if !t.unreachable {
                            if let Some(&src_reg) = t.reg_stack.last() {
                                if src_reg != result_reg {
                                    t.emit(Instruction::Copy {
                                        dst: result_reg,
                                        src: src_reg,
                                    });
                                }
                            }
                        }

                        // Finish current arm with jump to join
                        if !t.unreachable {
                            t.finish_block_and_switch_to(
                                Terminator::Jump { target: join_block },
                                join_block,
                            );
                        } else {
                            t.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                        }

                        t.reg_stack.truncate(scope.stack_height);

                        let reachable_after =
                            !scope.was_unreachable || scope.then_was_reachable || !t.unreachable;

                        if reachable_after {
                            t.reg_stack.push(result_reg);
                        }
                        t.unreachable = !reachable_after;
                    } else {
                        // No result, but still need to handle the else-block.
                        // If there was no Else operator, the else_block was allocated
                        // but never emitted into. We need to make it jump to join.
                        if !scope.then_was_reachable {
                            // No Else was encountered (then_was_reachable is only set in Else
                            // handler). The else_block needs to be a
                            // simple jump to join.
                            if let Some(else_block) = scope.else_block {
                                // Finish current (then) block
                                if !t.unreachable {
                                    t.finish_block_and_switch_to(
                                        Terminator::Jump { target: join_block },
                                        else_block,
                                    );
                                } else {
                                    t.finish_block_and_switch_to(
                                        Terminator::Unreachable,
                                        else_block,
                                    );
                                }
                                // else_block just jumps to join
                                t.finish_block_and_switch_to(
                                    Terminator::Jump { target: join_block },
                                    join_block,
                                );
                            }
                        } else {
                            // Else was encountered, we're finishing the else branch
                            if !t.unreachable {
                                t.finish_block_and_switch_to(
                                    Terminator::Jump { target: join_block },
                                    join_block,
                                );
                            } else {
                                t.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                            }
                        }

                        if t.unreachable {
                            t.reg_stack.truncate(scope.stack_height);
                        } else {
                            let target_height = scope.stack_height + scope.result_arity;
                            if t.reg_stack.len() >= target_height {
                                t.reg_stack.truncate(target_height);
                            }
                        }

                        // Reachability: if either branch was reachable
                        let reachable_after =
                            !scope.was_unreachable || scope.then_was_reachable || !t.unreachable;
                        t.unreachable = !reachable_after;
                    }
                } else {
                    // Regular block End
                    if let Some(result_reg) = scope.block_result_reg {
                        // Copy fall-through result to unified register
                        if !t.unreachable {
                            if let Some(&src_reg) = t.reg_stack.last() {
                                if src_reg != result_reg {
                                    t.emit(Instruction::Copy {
                                        dst: result_reg,
                                        src: src_reg,
                                    });
                                }
                            }
                        }

                        if !t.unreachable {
                            t.finish_block_and_switch_to(
                                Terminator::Jump { target: join_block },
                                join_block,
                            );
                        } else {
                            t.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                        }

                        t.reg_stack.truncate(scope.stack_height);

                        let reachable_after = !scope.was_unreachable;
                        if reachable_after {
                            t.reg_stack.push(result_reg);
                        }
                        t.unreachable = !reachable_after;
                    } else {
                        if !t.unreachable {
                            t.finish_block_and_switch_to(
                                Terminator::Jump { target: join_block },
                                join_block,
                            );
                        } else {
                            t.finish_block_and_switch_to(Terminator::Unreachable, join_block);
                        }

                        if t.unreachable {
                            t.reg_stack.truncate(scope.stack_height);
                        } else {
                            let target_height = scope.stack_height + scope.result_arity;
                            if t.reg_stack.len() >= target_height {
                                t.reg_stack.truncate(target_height);
                            }
                        }
                        t.unreachable = scope.was_unreachable;
                    }
                }
            }
            // Note: the outermost End (function body) has no scope entry;
            // it's handled by translate_to_registers after the loop.
        }
        Br { relative_depth } => {
            let depth = *relative_depth;
            let arity = t.branch_arity(depth);
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Copy to target block's result register
            if let (Some(&src), Some(dst)) = (values.first(), t.branch_result_reg(depth)) {
                if src != dst {
                    t.emit(Instruction::Copy { dst, src });
                }
            }

            match get_br_target(&t.scopes, depth) {
                Some(target) => {
                    t.finish_block(Terminator::Jump { target });
                }
                None => {
                    // Branch to function level = return
                    t.finish_block(Terminator::Return { values });
                }
            }
            t.set_unreachable();
        }
        BrIf { relative_depth } => {
            let depth = *relative_depth;
            let cond = t.pop()?;
            let arity = t.branch_arity(depth);
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Push values back since they may be used if branch not taken
            for r in values.iter().rev() {
                t.reg_stack.push(*r);
            }

            // Copy to target block's result register
            if let (Some(&src), Some(dst)) = (values.first(), t.branch_result_reg(depth)) {
                if src != dst {
                    t.emit(Instruction::Copy { dst, src });
                }
            }

            match get_br_target(&t.scopes, depth) {
                Some(target) => {
                    let fall_through = t.alloc_block();
                    let join = get_br_join(&t.scopes, depth).unwrap_or(fall_through);
                    t.finish_block_and_switch_to(
                        Terminator::BrCond {
                            cond,
                            then_target: target,
                            else_target: fall_through,
                            join,
                            region: BranchRegion::default(),
                        },
                        fall_through,
                    );
                }
                None => {
                    // Branch to function level = conditional return
                    // If taken: return. If not taken: continue.
                    let return_block = t.alloc_block();
                    let fall_through = t.alloc_block();
                    t.finish_block_and_switch_to(
                        Terminator::BrCond {
                            cond,
                            then_target: return_block,
                            else_target: fall_through,
                            join: fall_through,
                            region: BranchRegion::default(),
                        },
                        fall_through,
                    );
                    // Emit the return block
                    let saved_block = t.current_block;
                    t.current_block = return_block;
                    t.finish_block(Terminator::Return { values });
                    t.current_block = saved_block;
                }
            }
        }
        BrTable { targets } => {
            let table = targets.clone();
            let target_vec = table
                .targets()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let idx = t.pop()?;
            let arity = t.branch_arity(table.default());
            let values: Vec<Reg> = (0..arity).map(|_| t.pop()).collect::<Result<Vec<_>>>()?;

            // Copy to all unique target result registers
            if let Some(&src) = values.first() {
                let mut seen = std::collections::HashSet::new();
                for &depth in target_vec.iter().chain(std::iter::once(&table.default())) {
                    if let Some(dst) = t.branch_result_reg(depth) {
                        if src != dst && seen.insert(dst) {
                            t.emit(Instruction::Copy { dst, src });
                        }
                    }
                }
            }

            // For br_table targets that go to function level, create return blocks
            let mut block_targets: Vec<BlockId> = Vec::new();
            for &depth in &target_vec {
                match get_br_target(&t.scopes, depth) {
                    Some(target) => block_targets.push(target),
                    None => {
                        // Function-level branch = return block
                        let ret_block = t.alloc_block();
                        let saved = t.current_block;
                        t.current_block = ret_block;
                        t.finish_block(Terminator::Return {
                            values: values.clone(),
                        });
                        t.current_block = saved;
                        block_targets.push(ret_block);
                    }
                }
            }
            let default = match get_br_target(&t.scopes, table.default()) {
                Some(target) => target,
                None => {
                    let ret_block = t.alloc_block();
                    let saved = t.current_block;
                    t.current_block = ret_block;
                    t.finish_block(Terminator::Return {
                        values: values.clone(),
                    });
                    t.current_block = saved;
                    ret_block
                }
            };

            // Compute join as outermost target scope's continuation
            let default_depth = table.default();
            let max_depth = target_vec
                .iter()
                .chain(std::iter::once(&default_depth))
                .max()
                .copied()
                .unwrap_or(0);
            let join = get_br_join(&t.scopes, max_depth).unwrap_or_else(|| {
                // All targets are function-level returns; allocate a dummy
                // unreachable block as the join.
                let dummy = t.alloc_block();
                let saved = t.current_block;
                t.current_block = dummy;
                t.finish_block(Terminator::Unreachable);
                t.current_block = saved;
                dummy
            });

            t.finish_block(Terminator::BrTable {
                idx,
                targets: block_targets,
                default,
                join,
                region: BranchRegion::default(),
            });
            t.set_unreachable();
        }
        Return => {
            let values: Vec<Reg> = (0..func_type.results.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            t.finish_block(Terminator::Return { values });
            t.set_unreachable();
        }

        // === Calls ===
        Call { function_index } => {
            let callee_type = all_func_types
                .get(*function_index as usize)
                .ok_or_else(|| {
                    Error::Validation(format!("unknown function index {}", function_index))
                })?;
            let mut args: Vec<Reg> = (0..callee_type.params.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            args.reverse();

            let dst = if !callee_type.results.is_empty() {
                Some(t.push())
            } else {
                None
            };

            t.emit(Instruction::Call {
                dst,
                func_idx: *function_index,
                args,
            });
        }
        CallIndirect {
            type_index,
            table_index,
            ..
        } => {
            let table_idx = t.pop()?;
            let callee_type = all_types
                .get(*type_index as usize)
                .ok_or_else(|| Error::Validation(format!("unknown type index {}", type_index)))?;
            let mut args: Vec<Reg> = (0..callee_type.params.len())
                .map(|_| t.pop())
                .collect::<Result<Vec<_>>>()?;
            args.reverse();

            let dst = if !callee_type.results.is_empty() {
                Some(t.push())
            } else {
                None
            };

            t.emit(Instruction::CallIndirect {
                dst,
                type_index: *type_index,
                table_index: *table_index,
                table_idx,
                args,
            });
        }

        // === Parametric ===
        Drop => {
            t.pop()?;
        }
        Select | TypedSelect { .. } => {
            let cond = t.pop()?;
            let if_false = t.pop()?;
            let if_true = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::Select {
                dst,
                cond,
                if_true,
                if_false,
            });
        }

        // === Variables ===
        LocalGet { local_index } => {
            // Alias: push the local's register directly, no Copy.
            if !t.unreachable {
                t.reg_stack.push(*local_index);
            }
        }
        LocalSet { local_index } => {
            let src = t.pop()?;
            let dst = *local_index;
            if dst != src {
                // Materialize any aliases to this local on the stack.
                t.materialize_local(dst);
                t.emit(Instruction::Copy { dst, src });
            }
        }
        LocalTee { local_index } => {
            let src = t.peek()?;
            let dst = *local_index;
            if dst != src {
                t.materialize_local(dst);
                t.emit(Instruction::Copy { dst, src });
            }
        }
        GlobalGet { global_index } => {
            let dst = t.push();
            t.emit(Instruction::GlobalGet {
                dst,
                global_idx: *global_index,
            });
        }
        GlobalSet { global_index } => {
            let src = t.pop()?;
            t.emit(Instruction::GlobalSet {
                global_idx: *global_index,
                src,
            });
        }

        // === Memory Loads ===
        I32Load { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I32Load {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        F32Load { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::F32Load {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        F64Load { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::F64Load {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I32Load8S { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I32Load8S {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I32Load8U { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I32Load8U {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I32Load16S { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I32Load16S {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I32Load16U { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I32Load16U {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load8S { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load8S {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load8U { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load8U {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load16S { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load16S {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load16U { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load16U {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load32S { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load32S {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }
        I64Load32U { memarg } => {
            let addr = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::I64Load32U {
                dst,
                addr,
                memarg: parse_memarg(memarg),
            });
        }

        // === Memory Stores ===
        I32Store { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I32Store {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I64Store { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I64Store {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        F32Store { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::F32Store {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        F64Store { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::F64Store {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I32Store8 { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I32Store8 {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I32Store16 { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I32Store16 {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I64Store8 { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I64Store8 {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I64Store16 { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I64Store16 {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }
        I64Store32 { memarg } => {
            let val = t.pop()?;
            let addr = t.pop()?;
            t.emit(Instruction::I64Store32 {
                addr,
                val,
                memarg: parse_memarg(memarg),
            });
        }

        // === Memory Misc ===
        MemorySize { mem, .. } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            let dst = t.push();
            t.emit(Instruction::MemorySize { dst });
        }
        MemoryGrow { mem, .. } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            let pages = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::MemoryGrow { dst, pages });
        }
        MemoryFill { mem } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            let len = t.pop()?;
            let val = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryFill { dest, val, len });
        }
        MemoryCopy { dst_mem, src_mem } => {
            if *dst_mem != 0 || *src_mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            let len = t.pop()?;
            let src = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryCopy { dest, src, len });
        }
        MemoryInit { data_index, mem } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            let len = t.pop()?;
            let src_offset = t.pop()?;
            let dest = t.pop()?;
            t.emit(Instruction::MemoryInit {
                data_idx: *data_index,
                dest,
                src_offset,
                len,
            });
        }
        DataDrop { data_index } => {
            t.emit(Instruction::DataDrop {
                data_idx: *data_index,
            });
        }

        // === Constants ===
        I32Const { value } => {
            let dst = t.push();
            t.emit(Instruction::I32Const { dst, val: *value });
        }
        I64Const { value } => {
            let dst = t.push();
            t.emit(Instruction::I64Const { dst, val: *value });
        }
        F32Const { value } => {
            let dst = t.push();
            t.emit(Instruction::F32Const {
                dst,
                val: value.bits(),
            });
        }
        F64Const { value } => {
            let dst = t.push();
            t.emit(Instruction::F64Const {
                dst,
                val: value.bits(),
            });
        }

        // === References ===
        RefNull { hty } => {
            let ref_type = match hty {
                HeapType::Concrete(_) => {
                    return Err(Error::UnsupportedFeature(format!(
                        "concrete heap types not supported: {:?}",
                        hty
                    )));
                }
                HeapType::Abstract { shared: _, ty } => match ty {
                    wasmparser::AbstractHeapType::Func => RefType::FuncRef,
                    wasmparser::AbstractHeapType::Extern => RefType::ExternRef,
                    _ => {
                        return Err(Error::UnsupportedFeature(format!(
                            "unsupported abstract heap type: {:?}",
                            ty
                        )));
                    }
                },
            };
            let dst = t.push();
            t.emit(Instruction::RefNull { dst, ty: ref_type });
        }
        RefIsNull => {
            let src = t.pop()?;
            let dst = t.push();
            t.emit(Instruction::RefIsNull { dst, src });
        }
        RefFunc { function_index } => {
            let dst = t.push();
            t.emit(Instruction::RefFunc {
                dst,
                func_idx: *function_index,
            });
        }

        // === Arithmetic (unary) ===
        I32Eqz => t.unary_op(UnaryOp::I32Eqz)?,
        I64Eqz => t.unary_op(UnaryOp::I64Eqz)?,
        I32Clz => t.unary_op(UnaryOp::I32Clz)?,
        I32Ctz => t.unary_op(UnaryOp::I32Ctz)?,
        I32Popcnt => t.unary_op(UnaryOp::I32Popcnt)?,
        I64Clz => t.unary_op(UnaryOp::I64Clz)?,
        I64Ctz => t.unary_op(UnaryOp::I64Ctz)?,
        I64Popcnt => t.unary_op(UnaryOp::I64Popcnt)?,
        I32WrapI64 => t.unary_op(UnaryOp::I32WrapI64)?,
        I64ExtendI32S => t.unary_op(UnaryOp::I64ExtendI32S)?,
        I64ExtendI32U => t.unary_op(UnaryOp::I64ExtendI32U)?,
        I32Extend8S => t.unary_op(UnaryOp::I32Extend8S)?,
        I32Extend16S => t.unary_op(UnaryOp::I32Extend16S)?,
        I64Extend8S => t.unary_op(UnaryOp::I64Extend8S)?,
        I64Extend16S => t.unary_op(UnaryOp::I64Extend16S)?,
        I64Extend32S => t.unary_op(UnaryOp::I64Extend32S)?,
        F32Abs => t.unary_op(UnaryOp::F32Abs)?,
        F32Neg => t.unary_op(UnaryOp::F32Neg)?,
        F32Ceil => t.unary_op(UnaryOp::F32Ceil)?,
        F32Floor => t.unary_op(UnaryOp::F32Floor)?,
        F32Trunc => t.unary_op(UnaryOp::F32Trunc)?,
        F32Nearest => t.unary_op(UnaryOp::F32Nearest)?,
        F32Sqrt => t.unary_op(UnaryOp::F32Sqrt)?,
        F64Abs => t.unary_op(UnaryOp::F64Abs)?,
        F64Neg => t.unary_op(UnaryOp::F64Neg)?,
        F64Ceil => t.unary_op(UnaryOp::F64Ceil)?,
        F64Floor => t.unary_op(UnaryOp::F64Floor)?,
        F64Trunc => t.unary_op(UnaryOp::F64Trunc)?,
        F64Nearest => t.unary_op(UnaryOp::F64Nearest)?,
        F64Sqrt => t.unary_op(UnaryOp::F64Sqrt)?,
        I32TruncF32S => t.unary_op(UnaryOp::I32TruncF32S)?,
        I32TruncF32U => t.unary_op(UnaryOp::I32TruncF32U)?,
        I32TruncF64S => t.unary_op(UnaryOp::I32TruncF64S)?,
        I32TruncF64U => t.unary_op(UnaryOp::I32TruncF64U)?,
        I64TruncF32S => t.unary_op(UnaryOp::I64TruncF32S)?,
        I64TruncF32U => t.unary_op(UnaryOp::I64TruncF32U)?,
        I64TruncF64S => t.unary_op(UnaryOp::I64TruncF64S)?,
        I64TruncF64U => t.unary_op(UnaryOp::I64TruncF64U)?,
        F32ConvertI32S => t.unary_op(UnaryOp::F32ConvertI32S)?,
        F32ConvertI32U => t.unary_op(UnaryOp::F32ConvertI32U)?,
        F32ConvertI64S => t.unary_op(UnaryOp::F32ConvertI64S)?,
        F32ConvertI64U => t.unary_op(UnaryOp::F32ConvertI64U)?,
        F64ConvertI32S => t.unary_op(UnaryOp::F64ConvertI32S)?,
        F64ConvertI32U => t.unary_op(UnaryOp::F64ConvertI32U)?,
        F64ConvertI64S => t.unary_op(UnaryOp::F64ConvertI64S)?,
        F64ConvertI64U => t.unary_op(UnaryOp::F64ConvertI64U)?,
        F32DemoteF64 => t.unary_op(UnaryOp::F32DemoteF64)?,
        F64PromoteF32 => t.unary_op(UnaryOp::F64PromoteF32)?,
        I32ReinterpretF32 => t.unary_op(UnaryOp::I32ReinterpretF32)?,
        I64ReinterpretF64 => t.unary_op(UnaryOp::I64ReinterpretF64)?,
        F32ReinterpretI32 => t.unary_op(UnaryOp::F32ReinterpretI32)?,
        F64ReinterpretI64 => t.unary_op(UnaryOp::F64ReinterpretI64)?,
        I32TruncSatF32S => t.unary_op(UnaryOp::I32TruncSatF32S)?,
        I32TruncSatF32U => t.unary_op(UnaryOp::I32TruncSatF32U)?,
        I32TruncSatF64S => t.unary_op(UnaryOp::I32TruncSatF64S)?,
        I32TruncSatF64U => t.unary_op(UnaryOp::I32TruncSatF64U)?,
        I64TruncSatF32S => t.unary_op(UnaryOp::I64TruncSatF32S)?,
        I64TruncSatF32U => t.unary_op(UnaryOp::I64TruncSatF32U)?,
        I64TruncSatF64S => t.unary_op(UnaryOp::I64TruncSatF64S)?,
        I64TruncSatF64U => t.unary_op(UnaryOp::I64TruncSatF64U)?,

        // === Arithmetic (binary) ===
        I32Eq => t.binary_op(BinaryOp::I32Eq)?,
        I32Ne => t.binary_op(BinaryOp::I32Ne)?,
        I32LtS => t.binary_op(BinaryOp::I32LtS)?,
        I32LtU => t.binary_op(BinaryOp::I32LtU)?,
        I32GtS => t.binary_op(BinaryOp::I32GtS)?,
        I32GtU => t.binary_op(BinaryOp::I32GtU)?,
        I32LeS => t.binary_op(BinaryOp::I32LeS)?,
        I32LeU => t.binary_op(BinaryOp::I32LeU)?,
        I32GeS => t.binary_op(BinaryOp::I32GeS)?,
        I32GeU => t.binary_op(BinaryOp::I32GeU)?,
        I64Eq => t.binary_op(BinaryOp::I64Eq)?,
        I64Ne => t.binary_op(BinaryOp::I64Ne)?,
        I64LtS => t.binary_op(BinaryOp::I64LtS)?,
        I64LtU => t.binary_op(BinaryOp::I64LtU)?,
        I64GtS => t.binary_op(BinaryOp::I64GtS)?,
        I64GtU => t.binary_op(BinaryOp::I64GtU)?,
        I64LeS => t.binary_op(BinaryOp::I64LeS)?,
        I64LeU => t.binary_op(BinaryOp::I64LeU)?,
        I64GeS => t.binary_op(BinaryOp::I64GeS)?,
        I64GeU => t.binary_op(BinaryOp::I64GeU)?,
        I32Add => t.binary_op(BinaryOp::I32Add)?,
        I32Sub => t.binary_op(BinaryOp::I32Sub)?,
        I32Mul => t.binary_op(BinaryOp::I32Mul)?,
        I32DivS => t.binary_op(BinaryOp::I32DivS)?,
        I32DivU => t.binary_op(BinaryOp::I32DivU)?,
        I32RemS => t.binary_op(BinaryOp::I32RemS)?,
        I32RemU => t.binary_op(BinaryOp::I32RemU)?,
        I32And => t.binary_op(BinaryOp::I32And)?,
        I32Or => t.binary_op(BinaryOp::I32Or)?,
        I32Xor => t.binary_op(BinaryOp::I32Xor)?,
        I32Shl => t.binary_op(BinaryOp::I32Shl)?,
        I32ShrS => t.binary_op(BinaryOp::I32ShrS)?,
        I32ShrU => t.binary_op(BinaryOp::I32ShrU)?,
        I32Rotl => t.binary_op(BinaryOp::I32Rotl)?,
        I32Rotr => t.binary_op(BinaryOp::I32Rotr)?,
        I64Add => t.binary_op(BinaryOp::I64Add)?,
        I64Sub => t.binary_op(BinaryOp::I64Sub)?,
        I64Mul => t.binary_op(BinaryOp::I64Mul)?,
        I64DivS => t.binary_op(BinaryOp::I64DivS)?,
        I64DivU => t.binary_op(BinaryOp::I64DivU)?,
        I64RemS => t.binary_op(BinaryOp::I64RemS)?,
        I64RemU => t.binary_op(BinaryOp::I64RemU)?,
        I64And => t.binary_op(BinaryOp::I64And)?,
        I64Or => t.binary_op(BinaryOp::I64Or)?,
        I64Xor => t.binary_op(BinaryOp::I64Xor)?,
        I64Shl => t.binary_op(BinaryOp::I64Shl)?,
        I64ShrS => t.binary_op(BinaryOp::I64ShrS)?,
        I64ShrU => t.binary_op(BinaryOp::I64ShrU)?,
        I64Rotl => t.binary_op(BinaryOp::I64Rotl)?,
        I64Rotr => t.binary_op(BinaryOp::I64Rotr)?,
        F32Eq => t.binary_op(BinaryOp::F32Eq)?,
        F32Ne => t.binary_op(BinaryOp::F32Ne)?,
        F32Lt => t.binary_op(BinaryOp::F32Lt)?,
        F32Gt => t.binary_op(BinaryOp::F32Gt)?,
        F32Le => t.binary_op(BinaryOp::F32Le)?,
        F32Ge => t.binary_op(BinaryOp::F32Ge)?,
        F64Eq => t.binary_op(BinaryOp::F64Eq)?,
        F64Ne => t.binary_op(BinaryOp::F64Ne)?,
        F64Lt => t.binary_op(BinaryOp::F64Lt)?,
        F64Gt => t.binary_op(BinaryOp::F64Gt)?,
        F64Le => t.binary_op(BinaryOp::F64Le)?,
        F64Ge => t.binary_op(BinaryOp::F64Ge)?,
        F32Add => t.binary_op(BinaryOp::F32Add)?,
        F32Sub => t.binary_op(BinaryOp::F32Sub)?,
        F32Mul => t.binary_op(BinaryOp::F32Mul)?,
        F32Div => t.binary_op(BinaryOp::F32Div)?,
        F32Min => t.binary_op(BinaryOp::F32Min)?,
        F32Max => t.binary_op(BinaryOp::F32Max)?,
        F32Copysign => t.binary_op(BinaryOp::F32Copysign)?,
        F64Add => t.binary_op(BinaryOp::F64Add)?,
        F64Sub => t.binary_op(BinaryOp::F64Sub)?,
        F64Mul => t.binary_op(BinaryOp::F64Mul)?,
        F64Div => t.binary_op(BinaryOp::F64Div)?,
        F64Min => t.binary_op(BinaryOp::F64Min)?,
        F64Max => t.binary_op(BinaryOp::F64Max)?,
        F64Copysign => t.binary_op(BinaryOp::F64Copysign)?,

        _ => {
            return Err(Error::UnsupportedFeature(format!(
                "unsupported instruction: {:?}",
                op
            )));
        }
    }

    Ok(())
}

/// Get the branch target BlockId for a given depth from the scope stack.
/// Returns `None` if depth targets the function level (equivalent to return).
fn get_br_target(scopes: &[Scope], depth: u32) -> Option<BlockId> {
    let depth_usize = depth as usize;
    if depth_usize >= scopes.len() {
        None
    } else {
        let idx = scopes.len() - 1 - depth_usize;
        let scope = &scopes[idx];
        if scope.is_loop {
            Some(
                scope
                    .else_block
                    .expect("loop scope should have header in else_block"),
            )
        } else {
            Some(scope.continuation)
        }
    }
}

/// Get the join (immediate post-dominator) BlockId for a branch at the given
/// depth. Returns `None` if depth targets the function level (conditional
/// return), in which case the caller should use the fall-through block.
fn get_br_join(scopes: &[Scope], depth: u32) -> Option<BlockId> {
    let idx = scopes.len().checked_sub(1 + depth as usize)?;
    Some(scopes[idx].continuation)
}

/// Post-parse pass: compute `BranchRegion` for every `BrCond` and `BrTable`
/// terminator by walking all blocks reachable between the branch targets and
/// the join block.
fn compute_branch_regions(body: &mut FunctionBody) {
    // Collect (block_index, join) pairs for all BrCond/BrTable terminators.
    let branch_blocks: Vec<(usize, BlockId)> = body
        .blocks
        .iter()
        .enumerate()
        .filter_map(|(i, block)| match &block.terminator {
            Terminator::BrCond { join, .. } | Terminator::BrTable { join, .. } => Some((i, *join)),
            _ => None,
        })
        .collect();

    for (block_idx, join) in branch_blocks {
        // Collect all successor block IDs from the terminator.
        let starts: Vec<BlockId> = match &body.blocks[block_idx].terminator {
            Terminator::BrCond {
                then_target,
                else_target,
                ..
            } => vec![*then_target, *else_target],
            Terminator::BrTable {
                targets, default, ..
            } => {
                let mut s: Vec<BlockId> = targets.clone();
                s.push(*default);
                s
            }
            _ => unreachable!(),
        };

        let region = analyze_region(&body.blocks, &starts, join);
        match &mut body.blocks[block_idx].terminator {
            Terminator::BrCond { region: r, .. } | Terminator::BrTable { region: r, .. } => {
                *r = region;
            }
            _ => unreachable!(),
        }
    }
}

/// Walk all blocks reachable from `starts` up to (but not including) `join`,
/// collecting side-effect information.
fn analyze_region(blocks: &[BasicBlock], starts: &[BlockId], join: BlockId) -> BranchRegion {
    use std::collections::{HashSet, VecDeque};

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut has_memory_store = false;
    let mut has_call = false;
    let mut globals_written = HashSet::new();
    let mut registers_written = HashSet::new();
    let mut any_nontrivial_reaches_join = false;
    let mut has_nontrivial_start = false;

    for &start in starts {
        if start != join && visited.insert(start) {
            queue.push_back(start);
            has_nontrivial_start = true;
        }
    }

    while let Some(block_id) = queue.pop_front() {
        let block = match blocks.get(block_id.index()) {
            Some(b) => b,
            None => continue,
        };

        scan_block_side_effects(
            block,
            &mut has_memory_store,
            &mut has_call,
            &mut globals_written,
            &mut registers_written,
        );

        for succ in terminator_successors(&block.terminator) {
            if succ == join {
                any_nontrivial_reaches_join = true;
            } else if visited.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    let mut globals_vec: Vec<u32> = globals_written.into_iter().collect();
    globals_vec.sort_unstable();

    let mut regs_vec: Vec<Reg> = registers_written.into_iter().collect();
    regs_vec.sort_unstable();

    BranchRegion {
        has_memory_store,
        has_call,
        globals_written: globals_vec,
        registers_written: regs_vec,
        join_is_path_independent: any_nontrivial_reaches_join,
        bail_out: has_nontrivial_start
            && (!any_nontrivial_reaches_join
                || matches!(
                    blocks.get(join.index()).map(|b| &b.terminator),
                    Some(Terminator::Unreachable) | Some(Terminator::Return { .. })
                )),
    }
}

fn scan_block_side_effects(
    block: &BasicBlock,
    has_memory_store: &mut bool,
    has_call: &mut bool,
    globals_written: &mut std::collections::HashSet<u32>,
    registers_written: &mut std::collections::HashSet<Reg>,
) {
    for instr in &block.body {
        if let Some(dst) = instr.dst() {
            registers_written.insert(dst);
        }
        match instr {
            Instruction::GlobalSet { global_idx, .. } => {
                globals_written.insert(*global_idx);
            }
            Instruction::I32Store { .. }
            | Instruction::I64Store { .. }
            | Instruction::I32Store8 { .. }
            | Instruction::I32Store16 { .. }
            | Instruction::I64Store8 { .. }
            | Instruction::I64Store16 { .. }
            | Instruction::I64Store32 { .. }
            | Instruction::F32Store { .. }
            | Instruction::F64Store { .. }
            | Instruction::MemoryFill { .. }
            | Instruction::MemoryCopy { .. }
            | Instruction::MemoryInit { .. } => {
                *has_memory_store = true;
            }
            Instruction::Call { .. } | Instruction::CallIndirect { .. } => {
                *has_call = true;
            }
            _ => {}
        }
    }
}

fn terminator_successors(terminator: &Terminator) -> Vec<BlockId> {
    match terminator {
        Terminator::Jump { target } => vec![*target],
        Terminator::BrCond {
            then_target,
            else_target,
            ..
        } => vec![*then_target, *else_target],
        Terminator::BrTable {
            targets, default, ..
        } => {
            let mut s = targets.clone();
            s.push(*default);
            s
        }
        Terminator::Return { .. } | Terminator::Unreachable => vec![],
    }
}

fn block_type_result_arity(blockty: &WasmBlockType) -> usize {
    match blockty {
        WasmBlockType::Empty => 0,
        WasmBlockType::Type(_) => 1,
        WasmBlockType::FuncType(_) => 1, // Simplification; should look up type
    }
}

fn parse_memarg(memarg: &wasmparser::MemArg) -> MemArg {
    MemArg {
        align: memarg.align as u32,
        offset: memarg.offset as u32,
    }
}
