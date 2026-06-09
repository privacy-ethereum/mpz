mod parser;

#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    fmt,
    ops::Add,
    sync::Arc,
};

use thiserror::Error;

/// A register index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reg(pub u32);

impl Reg {
    /// Returns the register index as a `usize`.
    pub fn index(&self) -> usize {
        self.0 as usize
    }

    /// Returns the register index as a `u32`.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Returns the register `count` positions after this one.
    pub fn saturating_add(self, count: u32) -> Reg {
        Reg(self.0.saturating_add(count))
    }
}

impl Add<u32> for Reg {
    type Output = Reg;

    fn add(self, rhs: u32) -> Reg {
        Reg(self.0 + rhs)
    }
}

impl Add<Reg> for Reg {
    type Output = Reg;

    fn add(self, rhs: Reg) -> Reg {
        Reg(self.0 + rhs.0)
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
    },
    /// Multi-way branch (br_table).
    BrTable {
        idx: Reg,
        targets: Vec<BlockId>,
        default: BlockId,
        join: BlockId,
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
    Unsupported(#[from] UnsupportedFeature),
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
}

/// A WebAssembly feature that the parser does not support.
///
/// These are well-formed inputs that the translator deliberately rejects,
/// allowing consumers to classify the rejection without matching on strings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UnsupportedFeature {
    /// The binary is a component or otherwise not a plain module.
    #[error("only WebAssembly modules are supported")]
    NotAModule,
    /// A nested module section was encountered.
    #[error("nested modules not supported")]
    NestedModule,
    /// A component section was encountered.
    #[error("components not supported")]
    Component,
    /// A payload/section kind the parser does not handle.
    #[error("unsupported payload type: {0}")]
    Payload(String),
    /// A non-function, non-table, non-memory, non-global import.
    #[error("unsupported import type")]
    ImportType,
    /// A value type the parser does not model.
    #[error("unsupported value type: {0}")]
    ValType(String),
    /// A reference type the parser does not model.
    #[error("unsupported reference type: {0}")]
    RefType(String),
    /// An export kind the parser does not model.
    #[error("unsupported export kind")]
    ExportKind,
    /// A concrete heap type, which the parser does not support.
    #[error("concrete heap types not supported: {0}")]
    ConcreteHeapType(String),
    /// An abstract heap type the parser does not model.
    #[error("unsupported abstract heap type: {0}")]
    AbstractHeapType(String),
    /// An instruction not permitted in a constant expression.
    #[error("unsupported const expr instruction: {0}")]
    ConstExprInstruction(String),
    /// A constant expression containing more than one value-producing op.
    #[error("const expr with multiple operations")]
    MultiOpConstExpr,
    /// An instruction not permitted in an element segment expression.
    #[error("unsupported elem expr instruction: {0}")]
    ElemExprInstruction(String),
    /// A reference to a memory index other than 0 (multi-memory proposal).
    #[error("multi-memory not supported")]
    MultiMemory,
    /// An instruction opcode the translator does not implement.
    #[error("unsupported instruction: {0}")]
    Opcode(String),
}

/// A way in which the input module failed validation.
///
/// These indicate malformed or internally inconsistent input, as distinct from
/// well-formed-but-unsupported input ([`UnsupportedFeature`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// A type index that does not refer to a defined type.
    #[error("unknown type index {0}")]
    UnknownType(u32),
    /// A function index that does not refer to a defined function.
    #[error("unknown function index {0}")]
    UnknownFunction(u32),
    /// The number of data segments did not match the declared data count.
    #[error("data count mismatch: expected {expected}, got {actual}")]
    DataCountMismatch { expected: u32, actual: u32 },
    /// A constant expression produced no value.
    #[error("empty const expr")]
    EmptyConstExpr,
    /// An instruction popped from an empty operand stack.
    #[error("stack underflow")]
    StackUnderflow,
    /// A control-flow scope expected by the translator was missing.
    #[error("missing control flow scope: {0}")]
    MissingScope(&'static str),
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
    pub init: ConstExpr,
}

/// A constant expression, as used by global initializers and
/// element/data segment offsets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConstExpr {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
    GlobalGet(u32),
    RefFunc(u32),
    RefNull(RefType),
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
        offset: ConstExpr,
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
        offset: ConstExpr,
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

/// The width and extension of a memory load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadKind {
    /// `i32.load`: 4 bytes into an i32.
    I32,
    /// `i64.load`: 8 bytes into an i64.
    I64,
    /// `i32.load8_s`: 1 byte, sign-extended to i32.
    I32Load8S,
    /// `i32.load8_u`: 1 byte, zero-extended to i32.
    I32Load8U,
    /// `i32.load16_s`: 2 bytes, sign-extended to i32.
    I32Load16S,
    /// `i32.load16_u`: 2 bytes, zero-extended to i32.
    I32Load16U,
    /// `i64.load8_s`: 1 byte, sign-extended to i64.
    I64Load8S,
    /// `i64.load8_u`: 1 byte, zero-extended to i64.
    I64Load8U,
    /// `i64.load16_s`: 2 bytes, sign-extended to i64.
    I64Load16S,
    /// `i64.load16_u`: 2 bytes, zero-extended to i64.
    I64Load16U,
    /// `i64.load32_s`: 4 bytes, sign-extended to i64.
    I64Load32S,
    /// `i64.load32_u`: 4 bytes, zero-extended to i64.
    I64Load32U,
    /// `f32.load`: 4 bytes into an f32.
    F32,
    /// `f64.load`: 8 bytes into an f64.
    F64,
}

impl LoadKind {
    /// Returns the number of bytes read from memory.
    pub fn byte_size(&self) -> usize {
        use LoadKind::*;
        match self {
            I32 | F32 | I64Load32S | I64Load32U => 4,
            I64 | F64 => 8,
            I32Load8S | I32Load8U | I64Load8S | I64Load8U => 1,
            I32Load16S | I32Load16U | I64Load16S | I64Load16U => 2,
        }
    }

    /// Returns the type of the value written to the destination register.
    pub fn result_ty(&self) -> ValType {
        use LoadKind::*;
        match self {
            I32 | I32Load8S | I32Load8U | I32Load16S | I32Load16U => ValType::I32,
            I64 | I64Load8S | I64Load8U | I64Load16S | I64Load16U | I64Load32S | I64Load32U => {
                ValType::I64
            }
            F32 => ValType::F32,
            F64 => ValType::F64,
        }
    }

    /// Returns `true` if the loaded bytes are sign-extended (rather than
    /// zero-extended) when narrower than the result type. Full-width and
    /// floating-point loads report `false`.
    pub fn is_signed(&self) -> bool {
        use LoadKind::*;
        matches!(
            self,
            I32Load8S | I32Load16S | I64Load8S | I64Load16S | I64Load32S
        )
    }

    /// Returns `true` if this is a floating-point load.
    pub fn is_float(&self) -> bool {
        matches!(self, LoadKind::F32 | LoadKind::F64)
    }
}

/// The width of a memory store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// `i32.store`: stores all 4 bytes of an i32.
    I32,
    /// `i64.store`: stores all 8 bytes of an i64.
    I64,
    /// `i32.store8`: stores the low byte of an i32.
    I32Store8,
    /// `i32.store16`: stores the low 2 bytes of an i32.
    I32Store16,
    /// `i64.store8`: stores the low byte of an i64.
    I64Store8,
    /// `i64.store16`: stores the low 2 bytes of an i64.
    I64Store16,
    /// `i64.store32`: stores the low 4 bytes of an i64.
    I64Store32,
    /// `f32.store`: stores all 4 bytes of an f32.
    F32,
    /// `f64.store`: stores all 8 bytes of an f64.
    F64,
}

impl StoreKind {
    /// Returns the number of bytes written to memory.
    pub fn byte_size(&self) -> usize {
        use StoreKind::*;
        match self {
            I32 | F32 | I64Store32 => 4,
            I64 | F64 => 8,
            I32Store8 | I64Store8 => 1,
            I32Store16 | I64Store16 => 2,
        }
    }

    /// Returns the type of the value read from the source register.
    pub fn value_ty(&self) -> ValType {
        use StoreKind::*;
        match self {
            I32 | I32Store8 | I32Store16 => ValType::I32,
            I64 | I64Store8 | I64Store16 | I64Store32 => ValType::I64,
            F32 => ValType::F32,
            F64 => ValType::F64,
        }
    }

    /// Returns `true` if this is a narrowing store (the low bytes of a wider
    /// value), i.e. `*.store8`, `*.store16`, or `i64.store32`. Full-width
    /// stores report `false`.
    pub fn is_narrowing(&self) -> bool {
        use StoreKind::*;
        matches!(
            self,
            I32Store8 | I32Store16 | I64Store8 | I64Store16 | I64Store32
        )
    }

    /// Returns `true` if this is a floating-point store.
    pub fn is_float(&self) -> bool {
        matches!(self, StoreKind::F32 | StoreKind::F64)
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
    /// Loads a value from memory. The [`LoadKind`] selects the width and
    /// sign/zero extension.
    Load {
        kind: LoadKind,
        dst: Reg,
        addr: Reg,
        memarg: MemArg,
    },

    // === Memory Stores ===
    /// Stores a value to memory. The [`StoreKind`] selects the width.
    Store {
        kind: StoreKind,
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
            | Self::Load { dst, .. }
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
            | Self::Store { .. }
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
