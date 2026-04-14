mod parser;

#[cfg(test)]
mod tests;

use std::{collections::HashMap, sync::Arc};

use thiserror::Error;

/// A register index.
pub type Reg = u32;

/// A basic block identifier within a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId(pub u32);

impl BlockId {
    pub fn index(&self) -> usize {
        self.0 as usize
    }
}

/// A basic block: straight-line instructions followed by a terminator.
#[derive(Debug, Clone, PartialEq)]
pub struct BasicBlock {
    pub body: Vec<Instruction>,
    pub terminator: Terminator,
}

/// Precomputed side-effect info for all blocks reachable from a branch.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BranchRegion {
    pub has_memory_store: bool,
    pub has_call: bool,
    pub globals_written: Vec<u32>,
    pub registers_written: Vec<Reg>,
    /// Whether the join block is path-independent (all non-trivial paths
    /// reach it). When false, the delegate must run until function return.
    pub join_is_path_independent: bool,
    /// All non-trivial paths diverge (Return/Unreachable). The branch
    /// outcome is publicly deducible — not private CF.
    pub bail_out: bool,
}

/// A control flow terminator at the end of a basic block.
#[derive(Debug, Clone, PartialEq)]
pub enum Terminator {
    /// Unconditional jump.
    Jump { target: BlockId },
    /// Conditional branch.
    BrCond {
        cond: Reg,
        then_target: BlockId,
        else_target: BlockId,
        join: BlockId,
        region: BranchRegion,
    },
    /// Multi-way branch (br_table).
    BrTable {
        idx: Reg,
        targets: Vec<BlockId>,
        default: BlockId,
        join: BlockId,
        region: BranchRegion,
    },
    /// Return from function.
    Return { values: Vec<Reg> },
    /// Unconditional trap.
    Unreachable,
}

/// A function body represented as a control flow graph.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionBody {
    pub entry: BlockId,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("wasmparser error: {0}")]
    WasmParser(#[from] wasmparser::BinaryReaderError),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
    #[error("validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Module {
    types: Vec<FuncType>,
    functions: Vec<Function>,
    num_imported_funcs: usize,
    num_imported_tables: usize,
    tables: Vec<Table>,
    memories: Vec<Memory>,
    globals: Vec<Global>,
    exports: Vec<Export>,
    function_names: HashMap<u32, String>,
    start: Option<u32>,
    elements: Vec<Element>,
    data: Vec<Data>,
}

impl Module {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        parser::parse_module(bytes)
    }

    /// Returns the types defined in this module.
    pub fn types(&self) -> &[FuncType] {
        &self.types
    }

    /// Returns all functions (imports first, then local).
    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    /// Returns a function by index.
    pub fn function(&self, idx: u32) -> Option<&Function> {
        self.functions.get(idx as usize)
    }

    /// Returns the number of imported functions.
    pub fn imported_func_count(&self) -> usize {
        self.num_imported_funcs
    }

    /// Returns the number of imported tables.
    pub fn imported_table_count(&self) -> usize {
        self.num_imported_tables
    }

    /// Returns the tables defined in this module.
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// Returns the memories defined in this module.
    pub fn memories(&self) -> &[Memory] {
        &self.memories
    }

    /// Returns the globals defined in this module.
    pub fn globals(&self) -> &[Global] {
        &self.globals
    }

    /// Returns the exports defined in this module.
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    /// Returns the function names from the WASM name section.
    pub fn function_names(&self) -> &HashMap<u32, String> {
        &self.function_names
    }

    /// Returns the start function index if defined.
    pub fn start(&self) -> Option<u32> {
        self.start
    }

    /// Returns the element segments defined in this module.
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }

    /// Returns the data segments defined in this module.
    pub fn data(&self) -> &[Data] {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    /// 32-bit floating point (parsed but not executed - will trap at runtime)
    F32,
    /// 64-bit floating point (parsed but not executed - will trap at runtime)
    F64,
}

/// A WebAssembly function (either imported or defined in the module).
#[derive(Debug, Clone)]
pub enum Function {
    Import(ImportedFunction),
    Local(LocalFunction),
}

impl Function {
    /// Returns the function type.
    pub fn func_type(&self) -> &FuncType {
        match self {
            Function::Import(f) => f.func_type(),
            Function::Local(f) => f.func_type(),
        }
    }

    /// Returns true if this is an imported function.
    pub fn is_import(&self) -> bool {
        matches!(self, Function::Import(_))
    }

    /// Returns the local function if this is a local function.
    pub fn as_local(&self) -> Option<&LocalFunction> {
        match self {
            Function::Local(f) => Some(f),
            _ => None,
        }
    }

    /// Returns the imported function if this is an import.
    pub fn as_import(&self) -> Option<&ImportedFunction> {
        match self {
            Function::Import(f) => Some(f),
            _ => None,
        }
    }
}

/// An imported function.
#[derive(Debug, Clone)]
pub struct ImportedFunction {
    module: String,
    name: String,
    func_type: FuncType,
}

impl ImportedFunction {
    /// Creates a new imported function.
    pub fn new(module: String, name: String, func_type: FuncType) -> Self {
        Self {
            module,
            name,
            func_type,
        }
    }

    /// Returns the module name.
    pub fn module(&self) -> &str {
        &self.module
    }

    /// Returns the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the function type.
    pub fn func_type(&self) -> &FuncType {
        &self.func_type
    }
}

/// A locally defined function.
#[derive(Debug, Clone)]
pub struct LocalFunction {
    func_type: FuncType,
    locals: Arc<[Local]>,
    /// Number of registers used (params + locals + temporaries).
    num_regs: u32,
    body: FunctionBody,
}

impl LocalFunction {
    /// Creates a new local function.
    pub fn new(
        func_type: FuncType,
        locals: Arc<[Local]>,
        num_regs: u32,
        body: FunctionBody,
    ) -> Self {
        Self {
            func_type,
            locals,
            num_regs,
            body,
        }
    }

    /// Returns the number of registers used.
    pub fn register_count(&self) -> u32 {
        self.num_regs
    }

    /// Returns the function type.
    pub fn func_type(&self) -> &FuncType {
        &self.func_type
    }

    /// Returns the local variable definitions.
    pub fn locals(&self) -> &[Local] {
        &self.locals
    }

    /// Returns the function body as a CFG.
    pub fn body(&self) -> &FunctionBody {
        &self.body
    }
}

/// Non-function imports (table, memory, global).
#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub ty: ImportType,
}

/// Type of a non-function import.
#[derive(Debug, Clone, PartialEq)]
pub enum ImportType {
    Table(TableType),
    Memory(MemoryType),
    Global(GlobalType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Local {
    pub count: u32,
    pub ty: ValType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub ty: TableType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableType {
    pub element_type: RefType,
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefType {
    FuncRef,
    ExternRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub min: u64,
    pub max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Memory {
    pub ty: MemoryType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryType {
    pub limits: Limits,
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Global {
    pub ty: GlobalType,
    pub init: Vec<Instruction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalType {
    pub val_type: ValType,
    pub mutable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Export {
    pub name: String,
    pub kind: ExportKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Func(u32),
    Table(u32),
    Memory(u32),
    Global(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    pub kind: ElementKind,
    pub items: ElementItems,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ElementKind {
    Passive,
    Active {
        table_index: u32,
        offset: Vec<Instruction>,
    },
    Declared,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ElementItems {
    Functions(Vec<u32>),
    Expressions(RefType, Vec<Vec<Instruction>>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Data {
    pub kind: DataKind,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DataKind {
    Passive,
    Active {
        memory_index: u32,
        offset: Vec<Instruction>,
    },
}

/// Unary arithmetic operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    // Comparisons
    I32Eqz,
    I64Eqz,
    // i32 bit operations
    I32Clz,
    I32Ctz,
    I32Popcnt,
    // i64 bit operations
    I64Clz,
    I64Ctz,
    I64Popcnt,
    // Integer conversions
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    // f32 unary
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    // f64 unary
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    // Float-to-int conversions (trapping)
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    // Int-to-float conversions
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    // Float-to-float conversions
    F32DemoteF64,
    F64PromoteF32,
    // Reinterpret
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
    // Saturating truncations
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,
}

/// Binary arithmetic operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    // i32 comparisons
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    // i64 comparisons
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    // i32 arithmetic
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    // i64 arithmetic
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    // f32 comparisons
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    // f64 comparisons
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,
    // f32 binary arithmetic
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,
    // f64 binary arithmetic
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,
}

/// Unary arithmetic instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnaryArith {
    pub op: UnaryOp,
    pub dst: Reg,
    pub src: Reg,
}

/// Binary arithmetic instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BinaryArith {
    pub op: BinaryOp,
    pub dst: Reg,
    pub lhs: Reg,
    pub rhs: Reg,
}

impl UnaryOp {
    /// Returns the result type of this operation.
    pub fn return_ty(&self) -> ValType {
        use UnaryOp::*;
        match self {
            I32Eqz | I64Eqz => ValType::I32,
            I32Clz | I32Ctz | I32Popcnt => ValType::I32,
            I64Clz | I64Ctz | I64Popcnt => ValType::I64,
            I32WrapI64 | I32Extend8S | I32Extend16S => ValType::I32,
            I64ExtendI32S | I64ExtendI32U | I64Extend8S | I64Extend16S | I64Extend32S => {
                ValType::I64
            }
            F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc | F32Nearest | F32Sqrt => ValType::F32,
            F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc | F64Nearest | F64Sqrt => ValType::F64,
            I32TruncF32S | I32TruncF32U | I32TruncF64S | I32TruncF64U => ValType::I32,
            I64TruncF32S | I64TruncF32U | I64TruncF64S | I64TruncF64U => ValType::I64,
            F32ConvertI32S | F32ConvertI32U | F32ConvertI64S | F32ConvertI64U => ValType::F32,
            F64ConvertI32S | F64ConvertI32U | F64ConvertI64S | F64ConvertI64U => ValType::F64,
            F32DemoteF64 => ValType::F32,
            F64PromoteF32 => ValType::F64,
            I32ReinterpretF32 => ValType::I32,
            I64ReinterpretF64 => ValType::I64,
            F32ReinterpretI32 => ValType::F32,
            F64ReinterpretI64 => ValType::F64,
            I32TruncSatF32S | I32TruncSatF32U | I32TruncSatF64S | I32TruncSatF64U => ValType::I32,
            I64TruncSatF32S | I64TruncSatF32U | I64TruncSatF64S | I64TruncSatF64U => ValType::I64,
        }
    }

    /// Returns `true` if this is a floating-point operation.
    pub fn is_float(&self) -> bool {
        use UnaryOp::*;
        matches!(
            self,
            F32Abs
                | F32Neg
                | F32Ceil
                | F32Floor
                | F32Trunc
                | F32Nearest
                | F32Sqrt
                | F64Abs
                | F64Neg
                | F64Ceil
                | F64Floor
                | F64Trunc
                | F64Nearest
                | F64Sqrt
                | I32TruncF32S
                | I32TruncF32U
                | I32TruncF64S
                | I32TruncF64U
                | I64TruncF32S
                | I64TruncF32U
                | I64TruncF64S
                | I64TruncF64U
                | F32ConvertI32S
                | F32ConvertI32U
                | F32ConvertI64S
                | F32ConvertI64U
                | F64ConvertI32S
                | F64ConvertI32U
                | F64ConvertI64S
                | F64ConvertI64U
                | F32DemoteF64
                | F64PromoteF32
                | I32ReinterpretF32
                | I64ReinterpretF64
                | F32ReinterpretI32
                | F64ReinterpretI64
                | I32TruncSatF32S
                | I32TruncSatF32U
                | I32TruncSatF64S
                | I32TruncSatF64U
                | I64TruncSatF32S
                | I64TruncSatF32U
                | I64TruncSatF64S
                | I64TruncSatF64U
        )
    }
}

impl BinaryOp {
    /// Returns the result type of this operation.
    pub fn return_ty(&self) -> ValType {
        use BinaryOp::*;
        match self {
            // All comparisons return i32 (0 or 1)
            I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU | I32LeS | I32LeU | I32GeS
            | I32GeU | I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU | I64LeS | I64LeU
            | I64GeS | I64GeU | F32Eq | F32Ne | F32Lt | F32Gt | F32Le | F32Ge | F64Eq | F64Ne
            | F64Lt | F64Gt | F64Le | F64Ge => ValType::I32,
            // i32 arithmetic
            I32Add | I32Sub | I32Mul | I32DivS | I32DivU | I32RemS | I32RemU | I32And | I32Or
            | I32Xor | I32Shl | I32ShrS | I32ShrU | I32Rotl | I32Rotr => ValType::I32,
            // i64 arithmetic
            I64Add | I64Sub | I64Mul | I64DivS | I64DivU | I64RemS | I64RemU | I64And | I64Or
            | I64Xor | I64Shl | I64ShrS | I64ShrU | I64Rotl | I64Rotr => ValType::I64,
            // f32 arithmetic
            F32Add | F32Sub | F32Mul | F32Div | F32Min | F32Max | F32Copysign => ValType::F32,
            // f64 arithmetic
            F64Add | F64Sub | F64Mul | F64Div | F64Min | F64Max | F64Copysign => ValType::F64,
        }
    }

    /// Returns `true` if this is a floating-point operation.
    pub fn is_float(&self) -> bool {
        use BinaryOp::*;
        matches!(
            self,
            F32Eq
                | F32Ne
                | F32Lt
                | F32Gt
                | F32Le
                | F32Ge
                | F64Eq
                | F64Ne
                | F64Lt
                | F64Gt
                | F64Le
                | F64Ge
                | F32Add
                | F32Sub
                | F32Mul
                | F32Div
                | F32Min
                | F32Max
                | F32Copysign
                | F64Add
                | F64Sub
                | F64Mul
                | F64Div
                | F64Min
                | F64Max
                | F64Copysign
        )
    }
}

/// Arithmetic, bitwise, and floating-point operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionArith {
    Unary(UnaryArith),
    Binary(BinaryArith),
}

impl InstructionArith {
    /// Returns the result type of this instruction.
    pub fn return_ty(&self) -> ValType {
        match self {
            InstructionArith::Unary(u) => u.op.return_ty(),
            InstructionArith::Binary(b) => b.op.return_ty(),
        }
    }

    /// Returns the destination register.
    pub fn dst(&self) -> Reg {
        match self {
            InstructionArith::Unary(u) => u.dst,
            InstructionArith::Binary(b) => b.dst,
        }
    }

    /// Returns `true` if this is a floating-point instruction.
    pub fn is_float(&self) -> bool {
        match self {
            InstructionArith::Unary(u) => u.op.is_float(),
            InstructionArith::Binary(b) => b.op.is_float(),
        }
    }

    /// Returns the number of input operands for this arithmetic instruction.
    pub fn input_arity(&self) -> usize {
        match self {
            InstructionArith::Unary(_) => 1,
            InstructionArith::Binary(_) => 2,
        }
    }
}

/// Register-based WebAssembly instructions (straight-line only).
///
/// Each instruction that produces a value has an explicit destination register.
/// Each instruction that consumes values has explicit source registers.
/// Control flow is expressed via `Terminator` at the end of each `BasicBlock`.
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    Nop,

    // === Calls ===
    Call {
        dst: Option<Reg>,
        func_idx: u32,
        args: Vec<Reg>,
    },
    CallIndirect {
        dst: Option<Reg>,
        type_index: u32,
        table_index: u32,
        table_idx: Reg,
        args: Vec<Reg>,
    },

    // === Parametric ===
    Select {
        dst: Reg,
        cond: Reg,
        if_true: Reg,
        if_false: Reg,
    },

    // === Variables ===
    /// Copy value from one register to another.
    Copy {
        dst: Reg,
        src: Reg,
    },
    GlobalGet {
        dst: Reg,
        global_idx: u32,
    },
    GlobalSet {
        global_idx: u32,
        src: Reg,
    },

    // === Memory Loads ===
    I32Load {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I32Load8S {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I32Load8U {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I32Load16S {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I32Load16U {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load8S {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load8U {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load16S {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load16U {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load32S {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    I64Load32U {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    F32Load {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },
    F64Load {
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },

    // === Memory Stores ===
    I32Store {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I64Store {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I32Store8 {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I32Store16 {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I64Store8 {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I64Store16 {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    I64Store32 {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    F32Store {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },
    F64Store {
        addr: Reg,
        val: Reg,
        memarg: MemArg,
    },

    // === Memory Misc ===
    MemorySize {
        dst: Reg,
    },
    MemoryGrow {
        dst: Reg,
        pages: Reg,
    },
    MemoryFill {
        dest: Reg,
        val: Reg,
        len: Reg,
    },
    MemoryCopy {
        dest: Reg,
        src: Reg,
        len: Reg,
    },
    MemoryInit {
        data_idx: u32,
        dest: Reg,
        src_offset: Reg,
        len: Reg,
    },
    DataDrop {
        data_idx: u32,
    },

    // === Constants ===
    I32Const {
        dst: Reg,
        val: i32,
    },
    I64Const {
        dst: Reg,
        val: i64,
    },
    F32Const {
        dst: Reg,
        val: u32,
    },
    F64Const {
        dst: Reg,
        val: u64,
    },

    // === References ===
    RefNull {
        dst: Reg,
        ty: RefType,
    },
    RefIsNull {
        dst: Reg,
        src: Reg,
    },
    RefFunc {
        dst: Reg,
        func_idx: u32,
    },

    // === Arithmetic ===
    Arith(InstructionArith),
}

impl Instruction {
    /// Returns the destination register if this instruction writes one.
    pub fn dst(&self) -> Option<Reg> {
        match self {
            Self::Call { dst, .. } | Self::CallIndirect { dst, .. } => *dst,
            Self::Select { dst, .. }
            | Self::Copy { dst, .. }
            | Self::GlobalGet { dst, .. }
            | Self::I32Load { dst, .. }
            | Self::I64Load { dst, .. }
            | Self::I32Load8S { dst, .. }
            | Self::I32Load8U { dst, .. }
            | Self::I32Load16S { dst, .. }
            | Self::I32Load16U { dst, .. }
            | Self::I64Load8S { dst, .. }
            | Self::I64Load8U { dst, .. }
            | Self::I64Load16S { dst, .. }
            | Self::I64Load16U { dst, .. }
            | Self::I64Load32S { dst, .. }
            | Self::I64Load32U { dst, .. }
            | Self::F32Load { dst, .. }
            | Self::F64Load { dst, .. }
            | Self::MemorySize { dst }
            | Self::MemoryGrow { dst, .. }
            | Self::I32Const { dst, .. }
            | Self::I64Const { dst, .. }
            | Self::F32Const { dst, .. }
            | Self::F64Const { dst, .. }
            | Self::RefNull { dst, .. }
            | Self::RefIsNull { dst, .. }
            | Self::RefFunc { dst, .. } => Some(*dst),
            Self::Arith(a) => Some(a.dst()),
            Self::Nop
            | Self::GlobalSet { .. }
            | Self::I32Store { .. }
            | Self::I64Store { .. }
            | Self::I32Store8 { .. }
            | Self::I32Store16 { .. }
            | Self::I64Store8 { .. }
            | Self::I64Store16 { .. }
            | Self::I64Store32 { .. }
            | Self::F32Store { .. }
            | Self::F64Store { .. }
            | Self::MemoryFill { .. }
            | Self::MemoryCopy { .. }
            | Self::MemoryInit { .. }
            | Self::DataDrop { .. } => None,
        }
    }

    /// Returns `true` if this is an arithmetic instruction.
    pub fn is_arithmetic(&self) -> bool {
        matches!(self, Self::Arith(_))
    }
}

/// Memory access arguments for load and store instructions.
///
/// Specifies alignment hints and memory offsets for memory operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemArg {
    /// The alignment hint (expressed as the exponent of a power of 2).
    ///
    /// For example, align=2 means the memory access should be 4-byte aligned
    /// (2^2). This is a hint and does not affect semantics, only
    /// potentially performance.
    pub align: u32,

    /// Static offset added to the dynamic address from the stack.
    ///
    /// The effective address is computed as: stack_value + offset.
    pub offset: u32,
}

/// Type annotation for structured control instructions (block, loop, if).
///
/// Specifies what values the block consumes and produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockType {
    /// Empty block type: consumes and produces nothing.
    Empty,

    /// Single value type: produces one value of the given type.
    Type(ValType),

    /// Function type: uses a type from the module's type section.
    ///
    /// Allows blocks to consume and produce multiple values according to the
    /// function signature.
    FuncType(u32),
}
