use wasmparser::{
    Data as WasmData, DataKind as WasmDataKind, Element as WasmElement,
    ElementItems as WasmElementItems, ElementKind as WasmElementKind, Export as WasmExport,
    ExternalKind, Global as WasmGlobal, GlobalType as WasmGlobalType, HeapType,
    MemoryType as WasmMemoryType, RefType as WasmRefType, TableType as WasmTableType,
    ValType as WasmValType,
};

use crate::{
    Data, DataKind, Element, ElementItems, ElementKind, Export, ExportKind, FuncType, Global,
    GlobalType, Limits, Memory, MemoryType, RefType, Result, Table, TableType, UnsupportedFeature,
    ValType,
};

use super::const_expr::{parse_const_expr, parse_elem_expr};

pub(super) fn parse_func_type(ty: &wasmparser::FuncType) -> Result<FuncType> {
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

pub(super) fn parse_val_type(ty: WasmValType) -> Result<ValType> {
    match ty {
        WasmValType::I32 => Ok(ValType::I32),
        WasmValType::I64 => Ok(ValType::I64),
        WasmValType::F32 => Ok(ValType::F32),
        WasmValType::F64 => Ok(ValType::F64),
        _ => Err(UnsupportedFeature::ValType(format!("{:?}", ty)).into()),
    }
}

pub(super) fn parse_ref_type(ty: WasmRefType) -> Result<RefType> {
    if ty.is_func_ref() {
        Ok(RefType::FuncRef)
    } else if ty.is_extern_ref() {
        Ok(RefType::ExternRef)
    } else {
        Err(UnsupportedFeature::RefType(format!("{:?}", ty)).into())
    }
}

pub(super) fn parse_table(table_ty: &WasmTableType) -> Result<Table> {
    Ok(Table {
        ty: parse_table_type(table_ty)?,
    })
}

pub(super) fn parse_table_type(ty: &WasmTableType) -> Result<TableType> {
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

pub(super) fn parse_memory(memory_ty: &WasmMemoryType) -> Result<Memory> {
    Ok(Memory {
        ty: parse_memory_type(memory_ty)?,
    })
}

pub(super) fn parse_memory_type(ty: &WasmMemoryType) -> Result<MemoryType> {
    Ok(MemoryType {
        limits: Limits {
            min: ty.initial,
            max: ty.maximum,
        },
        shared: ty.shared,
    })
}

pub(super) fn parse_global(global: &WasmGlobal) -> Result<Global> {
    let mut reader = global.init_expr.get_binary_reader();
    let init = parse_const_expr(&mut reader)?;

    Ok(Global {
        ty: parse_global_type(&global.ty)?,
        init,
    })
}

pub(super) fn parse_global_type(ty: &WasmGlobalType) -> Result<GlobalType> {
    Ok(GlobalType {
        val_type: parse_val_type(ty.content_type)?,
        mutable: ty.mutable,
    })
}

pub(super) fn parse_export(export: &WasmExport) -> Result<Export> {
    let kind = match export.kind {
        ExternalKind::Func => ExportKind::Func(export.index),
        ExternalKind::Table => ExportKind::Table(export.index),
        ExternalKind::Memory => ExportKind::Memory(export.index),
        ExternalKind::Global => ExportKind::Global(export.index),
        _ => {
            return Err(UnsupportedFeature::ExportKind.into());
        }
    };

    Ok(Export {
        name: export.name.to_string(),
        kind,
    })
}

pub(super) fn parse_element(element: &WasmElement) -> Result<Element> {
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
                exprs.push(parse_elem_expr(&mut expr_reader)?);
            }
            ElementItems::Expressions(ref_type, exprs)
        }
    };

    Ok(Element { kind, items })
}

pub(super) fn parse_data(data: &WasmData) -> Result<Data> {
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

pub(super) fn parse_heap_type(hty: &HeapType) -> Result<RefType> {
    match hty {
        HeapType::Concrete(_) => {
            Err(UnsupportedFeature::ConcreteHeapType(format!("{:?}", hty)).into())
        }
        HeapType::Abstract { shared: _, ty } => match ty {
            wasmparser::AbstractHeapType::Func => Ok(RefType::FuncRef),
            wasmparser::AbstractHeapType::Extern => Ok(RefType::ExternRef),
            _ => Err(UnsupportedFeature::AbstractHeapType(format!("{:?}", ty)).into()),
        },
    }
}
