mod cfg;
mod const_expr;
mod sections;
mod translate;

use wasmparser::{BinaryReader, CompositeInnerType, Parser, Payload, TypeRef};

use crate::{
    Data, Element, Export, FuncType, Function, Global, GlobalType, ImportedFunction, Local,
    LocalFunction, Memory, MemoryType, Module, Result, Table, TableType, UnsupportedFeature,
    ValidationError,
};

use sections::{
    parse_data, parse_element, parse_export, parse_func_type, parse_global, parse_global_type,
    parse_memory, parse_memory_type, parse_table, parse_table_type, parse_val_type,
};
use translate::translate_to_registers;

/// Non-function imports (table, memory, global).
#[derive(Debug, Clone, PartialEq)]
struct Import {
    module: String,
    name: String,
    ty: ImportType,
}

/// Type of a non-function import.
#[derive(Debug, Clone, PartialEq)]
enum ImportType {
    Table(TableType),
    Memory(MemoryType),
    Global(GlobalType),
}

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
                    return Err(UnsupportedFeature::NotAModule.into());
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
                            return Err(UnsupportedFeature::ImportType.into());
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
                return Err(UnsupportedFeature::NestedModule.into());
            }
            Payload::ComponentSection { .. } => {
                return Err(UnsupportedFeature::Component.into());
            }
            Payload::UnknownSection { .. } => {
                // Skip unknown sections
            }
            Payload::End(_) => {}
            other => {
                return Err(UnsupportedFeature::Payload(format!("{:?}", other)).into());
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
            .ok_or(ValidationError::UnknownType(*type_idx))?;
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
            .ok_or(ValidationError::UnknownType(*type_idx))?;
        func_type_lookup.push(func_type);
    }
    for type_idx in &function_type_indices {
        let func_type = types
            .get(*type_idx as usize)
            .cloned()
            .ok_or(ValidationError::UnknownType(*type_idx))?;
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
            .ok_or(ValidationError::UnknownType(*type_idx))?;

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
    if let Some(count) = data_count
        && data.len() != count as usize
    {
        return Err(ValidationError::DataCountMismatch {
            expected: count,
            actual: data.len() as u32,
        }
        .into());
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
