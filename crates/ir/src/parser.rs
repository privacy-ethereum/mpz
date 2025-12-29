use wasmparser::{
    BinaryReader, BlockType as WasmBlockType, CompositeInnerType, Data as WasmData,
    DataKind as WasmDataKind, Element as WasmElement, ElementItems as WasmElementItems,
    ElementKind as WasmElementKind, Export as WasmExport, ExternalKind, Global as WasmGlobal,
    GlobalType as WasmGlobalType, HeapType, MemoryType as WasmMemoryType, Operator, Parser,
    Payload, RefType as WasmRefType, TableType as WasmTableType, TypeRef, ValType as WasmValType,
};

use crate::{
    BlockType, Data, DataKind, Element, ElementItems, ElementKind, Error, Export, ExportKind,
    FuncType, Function, Global, GlobalType, Import, ImportType, ImportedFunction, Instruction,
    InstructionArith, Limits, Local, LocalFunction, MemArg, Memory, MemoryType, Module, RefType,
    Result, Table, TableType, ValType,
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
            Payload::CustomSection { .. } => {
                // Skip custom sections
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

    // Build imported functions first (imports come before local functions in indexing)
    let num_imported_funcs = func_imports.len();
    for (module_name, name, type_idx) in func_imports {
        let func_type = types
            .get(type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::UnsupportedFeature("invalid type index".to_string()))?;
        functions.push(Function::Import(ImportedFunction::new(
            module_name,
            name,
            func_type,
        )));
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

        let instructions = parse_instructions(&mut reader)?;

        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or_else(|| Error::UnsupportedFeature("invalid type index".to_string()))?;

        functions.push(Function::Local(LocalFunction::new(
            func_type,
            locals.into(),
            instructions.into(),
        )));
    }

    // Validate data count if present
    if let Some(count) = data_count {
        if data.len() != count as usize {
            return Err(Error::UnsupportedFeature(format!(
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
    let init = parse_instructions(&mut reader)?;

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
            let offset = parse_instructions(&mut reader)?;
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
                exprs.push(parse_instructions(&mut expr_reader)?);
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
            let offset = parse_instructions(&mut reader)?;
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

fn parse_instructions(reader: &mut BinaryReader) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();

    while !reader.eof() {
        let op = reader.read_operator()?;
        if let Some(instr) = parse_operator(&op)? {
            instructions.push(instr);
        }
    }

    Ok(instructions)
}

fn parse_operator(op: &Operator) -> Result<Option<Instruction>> {
    use Operator::*;

    let instr = match op {
        Unreachable => Instruction::Unreachable,
        Nop => Instruction::Nop,
        Block { blockty } => Instruction::Block {
            blockty: parse_block_type(blockty)?,
        },
        Loop { blockty } => Instruction::Loop {
            blockty: parse_block_type(blockty)?,
        },
        If { blockty } => Instruction::If {
            blockty: parse_block_type(blockty)?,
        },
        Else => Instruction::Else,
        End => Instruction::End,
        Br { relative_depth } => Instruction::Br(*relative_depth),
        BrIf { relative_depth } => Instruction::BrIf(*relative_depth),
        BrTable { targets } => {
            let table = targets.clone();
            let target_vec = table
                .targets()
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Instruction::BrTable {
                targets: target_vec,
                default: table.default(),
            }
        }
        Return => Instruction::Return,
        Call { function_index } => Instruction::Call(*function_index),
        CallIndirect {
            type_index,
            table_index,
            ..
        } => Instruction::CallIndirect {
            type_index: *type_index,
            table_index: *table_index,
        },
        Drop => Instruction::Drop,
        Select => Instruction::Select,
        TypedSelect { ty } => Instruction::SelectTyped(vec![parse_val_type(*ty)?]),
        LocalGet { local_index } => Instruction::LocalGet(*local_index),
        LocalSet { local_index } => Instruction::LocalSet(*local_index),
        LocalTee { local_index } => Instruction::LocalTee(*local_index),
        GlobalGet { global_index } => Instruction::GlobalGet(*global_index),
        GlobalSet { global_index } => Instruction::GlobalSet(*global_index),
        I32Load { memarg } => Instruction::I32Load(parse_memarg(memarg)),
        I64Load { memarg } => Instruction::I64Load(parse_memarg(memarg)),
        F32Load { memarg } => Instruction::F32Load(parse_memarg(memarg)),
        F64Load { memarg } => Instruction::F64Load(parse_memarg(memarg)),
        I32Load8S { memarg } => Instruction::I32Load8S(parse_memarg(memarg)),
        I32Load8U { memarg } => Instruction::I32Load8U(parse_memarg(memarg)),
        I32Load16S { memarg } => Instruction::I32Load16S(parse_memarg(memarg)),
        I32Load16U { memarg } => Instruction::I32Load16U(parse_memarg(memarg)),
        I64Load8S { memarg } => Instruction::I64Load8S(parse_memarg(memarg)),
        I64Load8U { memarg } => Instruction::I64Load8U(parse_memarg(memarg)),
        I64Load16S { memarg } => Instruction::I64Load16S(parse_memarg(memarg)),
        I64Load16U { memarg } => Instruction::I64Load16U(parse_memarg(memarg)),
        I64Load32S { memarg } => Instruction::I64Load32S(parse_memarg(memarg)),
        I64Load32U { memarg } => Instruction::I64Load32U(parse_memarg(memarg)),
        I32Store { memarg } => Instruction::I32Store(parse_memarg(memarg)),
        I64Store { memarg } => Instruction::I64Store(parse_memarg(memarg)),
        F32Store { memarg } => Instruction::F32Store(parse_memarg(memarg)),
        F64Store { memarg } => Instruction::F64Store(parse_memarg(memarg)),
        I32Store8 { memarg } => Instruction::I32Store8(parse_memarg(memarg)),
        I32Store16 { memarg } => Instruction::I32Store16(parse_memarg(memarg)),
        I64Store8 { memarg } => Instruction::I64Store8(parse_memarg(memarg)),
        I64Store16 { memarg } => Instruction::I64Store16(parse_memarg(memarg)),
        I64Store32 { memarg } => Instruction::I64Store32(parse_memarg(memarg)),
        MemorySize { mem, .. } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            Instruction::MemorySize
        }
        MemoryGrow { mem, .. } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            Instruction::MemoryGrow
        }
        MemoryFill { mem } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            Instruction::MemoryFill
        }
        MemoryCopy { dst_mem, src_mem } => {
            if *dst_mem != 0 || *src_mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            Instruction::MemoryCopy
        }
        MemoryInit { data_index, mem } => {
            if *mem != 0 {
                return Err(Error::UnsupportedFeature(
                    "multi-memory not supported".to_string(),
                ));
            }
            Instruction::MemoryInit(*data_index)
        }
        DataDrop { data_index } => Instruction::DataDrop(*data_index),
        I32Const { value } => Instruction::I32Const(*value),
        I64Const { value } => Instruction::I64Const(*value),
        F32Const { value } => Instruction::F32Const(value.bits()),
        F64Const { value } => Instruction::F64Const(value.bits()),
        RefNull { hty } => {
            let ref_type = match hty {
                HeapType::Concrete(_) => {
                    // For concrete types, check if it's a function or extern
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
            Instruction::RefNull(ref_type)
        }
        RefIsNull => Instruction::RefIsNull,
        RefFunc { function_index } => Instruction::RefFunc(*function_index),
        I32Eqz => Instruction::Arith(InstructionArith::I32Eqz),
        I32Eq => Instruction::Arith(InstructionArith::I32Eq),
        I32Ne => Instruction::Arith(InstructionArith::I32Ne),
        I32LtS => Instruction::Arith(InstructionArith::I32LtS),
        I32LtU => Instruction::Arith(InstructionArith::I32LtU),
        I32GtS => Instruction::Arith(InstructionArith::I32GtS),
        I32GtU => Instruction::Arith(InstructionArith::I32GtU),
        I32LeS => Instruction::Arith(InstructionArith::I32LeS),
        I32LeU => Instruction::Arith(InstructionArith::I32LeU),
        I32GeS => Instruction::Arith(InstructionArith::I32GeS),
        I32GeU => Instruction::Arith(InstructionArith::I32GeU),
        I64Eqz => Instruction::Arith(InstructionArith::I64Eqz),
        I64Eq => Instruction::Arith(InstructionArith::I64Eq),
        I64Ne => Instruction::Arith(InstructionArith::I64Ne),
        I64LtS => Instruction::Arith(InstructionArith::I64LtS),
        I64LtU => Instruction::Arith(InstructionArith::I64LtU),
        I64GtS => Instruction::Arith(InstructionArith::I64GtS),
        I64GtU => Instruction::Arith(InstructionArith::I64GtU),
        I64LeS => Instruction::Arith(InstructionArith::I64LeS),
        I64LeU => Instruction::Arith(InstructionArith::I64LeU),
        I64GeS => Instruction::Arith(InstructionArith::I64GeS),
        I64GeU => Instruction::Arith(InstructionArith::I64GeU),
        F32Eq => Instruction::Arith(InstructionArith::F32Eq),
        F32Ne => Instruction::Arith(InstructionArith::F32Ne),
        F32Lt => Instruction::Arith(InstructionArith::F32Lt),
        F32Gt => Instruction::Arith(InstructionArith::F32Gt),
        F32Le => Instruction::Arith(InstructionArith::F32Le),
        F32Ge => Instruction::Arith(InstructionArith::F32Ge),
        F64Eq => Instruction::Arith(InstructionArith::F64Eq),
        F64Ne => Instruction::Arith(InstructionArith::F64Ne),
        F64Lt => Instruction::Arith(InstructionArith::F64Lt),
        F64Gt => Instruction::Arith(InstructionArith::F64Gt),
        F64Le => Instruction::Arith(InstructionArith::F64Le),
        F64Ge => Instruction::Arith(InstructionArith::F64Ge),
        I32Clz => Instruction::Arith(InstructionArith::I32Clz),
        I32Ctz => Instruction::Arith(InstructionArith::I32Ctz),
        I32Popcnt => Instruction::Arith(InstructionArith::I32Popcnt),
        I32Add => Instruction::Arith(InstructionArith::I32Add),
        I32Sub => Instruction::Arith(InstructionArith::I32Sub),
        I32Mul => Instruction::Arith(InstructionArith::I32Mul),
        I32DivS => Instruction::Arith(InstructionArith::I32DivS),
        I32DivU => Instruction::Arith(InstructionArith::I32DivU),
        I32RemS => Instruction::Arith(InstructionArith::I32RemS),
        I32RemU => Instruction::Arith(InstructionArith::I32RemU),
        I32And => Instruction::Arith(InstructionArith::I32And),
        I32Or => Instruction::Arith(InstructionArith::I32Or),
        I32Xor => Instruction::Arith(InstructionArith::I32Xor),
        I32Shl => Instruction::Arith(InstructionArith::I32Shl),
        I32ShrS => Instruction::Arith(InstructionArith::I32ShrS),
        I32ShrU => Instruction::Arith(InstructionArith::I32ShrU),
        I32Rotl => Instruction::Arith(InstructionArith::I32Rotl),
        I32Rotr => Instruction::Arith(InstructionArith::I32Rotr),
        I64Clz => Instruction::Arith(InstructionArith::I64Clz),
        I64Ctz => Instruction::Arith(InstructionArith::I64Ctz),
        I64Popcnt => Instruction::Arith(InstructionArith::I64Popcnt),
        I64Add => Instruction::Arith(InstructionArith::I64Add),
        I64Sub => Instruction::Arith(InstructionArith::I64Sub),
        I64Mul => Instruction::Arith(InstructionArith::I64Mul),
        I64DivS => Instruction::Arith(InstructionArith::I64DivS),
        I64DivU => Instruction::Arith(InstructionArith::I64DivU),
        I64RemS => Instruction::Arith(InstructionArith::I64RemS),
        I64RemU => Instruction::Arith(InstructionArith::I64RemU),
        I64And => Instruction::Arith(InstructionArith::I64And),
        I64Or => Instruction::Arith(InstructionArith::I64Or),
        I64Xor => Instruction::Arith(InstructionArith::I64Xor),
        I64Shl => Instruction::Arith(InstructionArith::I64Shl),
        I64ShrS => Instruction::Arith(InstructionArith::I64ShrS),
        I64ShrU => Instruction::Arith(InstructionArith::I64ShrU),
        I64Rotl => Instruction::Arith(InstructionArith::I64Rotl),
        I64Rotr => Instruction::Arith(InstructionArith::I64Rotr),
        F32Abs => Instruction::Arith(InstructionArith::F32Abs),
        F32Neg => Instruction::Arith(InstructionArith::F32Neg),
        F32Ceil => Instruction::Arith(InstructionArith::F32Ceil),
        F32Floor => Instruction::Arith(InstructionArith::F32Floor),
        F32Trunc => Instruction::Arith(InstructionArith::F32Trunc),
        F32Nearest => Instruction::Arith(InstructionArith::F32Nearest),
        F32Sqrt => Instruction::Arith(InstructionArith::F32Sqrt),
        F32Add => Instruction::Arith(InstructionArith::F32Add),
        F32Sub => Instruction::Arith(InstructionArith::F32Sub),
        F32Mul => Instruction::Arith(InstructionArith::F32Mul),
        F32Div => Instruction::Arith(InstructionArith::F32Div),
        F32Min => Instruction::Arith(InstructionArith::F32Min),
        F32Max => Instruction::Arith(InstructionArith::F32Max),
        F32Copysign => Instruction::Arith(InstructionArith::F32Copysign),
        F64Abs => Instruction::Arith(InstructionArith::F64Abs),
        F64Neg => Instruction::Arith(InstructionArith::F64Neg),
        F64Ceil => Instruction::Arith(InstructionArith::F64Ceil),
        F64Floor => Instruction::Arith(InstructionArith::F64Floor),
        F64Trunc => Instruction::Arith(InstructionArith::F64Trunc),
        F64Nearest => Instruction::Arith(InstructionArith::F64Nearest),
        F64Sqrt => Instruction::Arith(InstructionArith::F64Sqrt),
        F64Add => Instruction::Arith(InstructionArith::F64Add),
        F64Sub => Instruction::Arith(InstructionArith::F64Sub),
        F64Mul => Instruction::Arith(InstructionArith::F64Mul),
        F64Div => Instruction::Arith(InstructionArith::F64Div),
        F64Min => Instruction::Arith(InstructionArith::F64Min),
        F64Max => Instruction::Arith(InstructionArith::F64Max),
        F64Copysign => Instruction::Arith(InstructionArith::F64Copysign),
        I32WrapI64 => Instruction::Arith(InstructionArith::I32WrapI64),
        I64ExtendI32S => Instruction::Arith(InstructionArith::I64ExtendI32S),
        I64ExtendI32U => Instruction::Arith(InstructionArith::I64ExtendI32U),
        I32TruncF32S => Instruction::Arith(InstructionArith::I32TruncF32S),
        I32TruncF32U => Instruction::Arith(InstructionArith::I32TruncF32U),
        I32TruncF64S => Instruction::Arith(InstructionArith::I32TruncF64S),
        I32TruncF64U => Instruction::Arith(InstructionArith::I32TruncF64U),
        I64TruncF32S => Instruction::Arith(InstructionArith::I64TruncF32S),
        I64TruncF32U => Instruction::Arith(InstructionArith::I64TruncF32U),
        I64TruncF64S => Instruction::Arith(InstructionArith::I64TruncF64S),
        I64TruncF64U => Instruction::Arith(InstructionArith::I64TruncF64U),
        F32ConvertI32S => Instruction::Arith(InstructionArith::F32ConvertI32S),
        F32ConvertI32U => Instruction::Arith(InstructionArith::F32ConvertI32U),
        F32ConvertI64S => Instruction::Arith(InstructionArith::F32ConvertI64S),
        F32ConvertI64U => Instruction::Arith(InstructionArith::F32ConvertI64U),
        F64ConvertI32S => Instruction::Arith(InstructionArith::F64ConvertI32S),
        F64ConvertI32U => Instruction::Arith(InstructionArith::F64ConvertI32U),
        F64ConvertI64S => Instruction::Arith(InstructionArith::F64ConvertI64S),
        F64ConvertI64U => Instruction::Arith(InstructionArith::F64ConvertI64U),
        F32DemoteF64 => Instruction::Arith(InstructionArith::F32DemoteF64),
        F64PromoteF32 => Instruction::Arith(InstructionArith::F64PromoteF32),
        I32ReinterpretF32 => Instruction::Arith(InstructionArith::I32ReinterpretF32),
        I64ReinterpretF64 => Instruction::Arith(InstructionArith::I64ReinterpretF64),
        F32ReinterpretI32 => Instruction::Arith(InstructionArith::F32ReinterpretI32),
        F64ReinterpretI64 => Instruction::Arith(InstructionArith::F64ReinterpretI64),
        I32Extend8S => Instruction::Arith(InstructionArith::I32Extend8S),
        I32Extend16S => Instruction::Arith(InstructionArith::I32Extend16S),
        I64Extend8S => Instruction::Arith(InstructionArith::I64Extend8S),
        I64Extend16S => Instruction::Arith(InstructionArith::I64Extend16S),
        I64Extend32S => Instruction::Arith(InstructionArith::I64Extend32S),
        I32TruncSatF32S => Instruction::Arith(InstructionArith::I32TruncSatF32S),
        I32TruncSatF32U => Instruction::Arith(InstructionArith::I32TruncSatF32U),
        I32TruncSatF64S => Instruction::Arith(InstructionArith::I32TruncSatF64S),
        I32TruncSatF64U => Instruction::Arith(InstructionArith::I32TruncSatF64U),
        I64TruncSatF32S => Instruction::Arith(InstructionArith::I64TruncSatF32S),
        I64TruncSatF32U => Instruction::Arith(InstructionArith::I64TruncSatF32U),
        I64TruncSatF64S => Instruction::Arith(InstructionArith::I64TruncSatF64S),
        I64TruncSatF64U => Instruction::Arith(InstructionArith::I64TruncSatF64U),
        _ => {
            return Err(Error::UnsupportedFeature(format!(
                "unsupported instruction: {:?}",
                op
            )));
        }
    };

    Ok(Some(instr))
}

fn parse_block_type(blockty: &WasmBlockType) -> Result<BlockType> {
    match blockty {
        WasmBlockType::Empty => Ok(BlockType::Empty),
        WasmBlockType::Type(ty) => Ok(BlockType::Type(parse_val_type(*ty)?)),
        WasmBlockType::FuncType(idx) => Ok(BlockType::FuncType(*idx)),
    }
}

fn parse_memarg(memarg: &wasmparser::MemArg) -> MemArg {
    MemArg {
        align: memarg.align as u32,
        offset: memarg.offset as u32,
    }
}
