mod parser;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("wasmparser error: {0}")]
    WasmParser(#[from] wasmparser::BinaryReaderError),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
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
    body: Arc<[Instruction]>,
}

impl LocalFunction {
    /// Creates a new local function.
    pub fn new(func_type: FuncType, locals: Arc<[Local]>, body: Arc<[Instruction]>) -> Self {
        Self {
            func_type,
            locals,
            body,
        }
    }

    /// Returns the function type.
    pub fn func_type(&self) -> &FuncType {
        &self.func_type
    }

    /// Returns the local variable definitions.
    pub fn locals(&self) -> &[Local] {
        &self.locals
    }

    /// Returns the function body.
    pub fn body(&self) -> &Arc<[Instruction]> {
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

/// Arithmetic, bitwise, and floating-point operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionArith {
    // i32 Comparisons
    I32Eqz,
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

    // i64 Comparisons
    I64Eqz,
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

    // i32 Arithmetic
    I32Clz,
    I32Ctz,
    I32Popcnt,
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

    // i64 Arithmetic
    I64Clz,
    I64Ctz,
    I64Popcnt,
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

    // Integer Conversion Instructions
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,

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

    // f32 arithmetic
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,

    // f64 arithmetic
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,

    // Float conversions
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    F32DemoteF64,
    F64PromoteF32,
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

impl InstructionArith {
    /// Returns the result type of this instruction.
    pub fn return_ty(&self) -> ValType {
        use InstructionArith::*;
        match self {
            // All integer comparisons return i32 (0 or 1)
            I32Eqz | I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU | I32LeS | I32LeU
            | I32GeS | I32GeU | I64Eqz | I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU
            | I64LeS | I64LeU | I64GeS | I64GeU => ValType::I32,

            // i32 arithmetic operations
            I32Clz | I32Ctz | I32Popcnt | I32Add | I32Sub | I32Mul | I32DivS | I32DivU
            | I32RemS | I32RemU | I32And | I32Or | I32Xor | I32Shl | I32ShrS | I32ShrU
            | I32Rotl | I32Rotr => ValType::I32,

            // i64 arithmetic operations
            I64Clz | I64Ctz | I64Popcnt | I64Add | I64Sub | I64Mul | I64DivS | I64DivU
            | I64RemS | I64RemU | I64And | I64Or | I64Xor | I64Shl | I64ShrS | I64ShrU
            | I64Rotl | I64Rotr => ValType::I64,

            // Integer conversions
            I32WrapI64 | I32Extend8S | I32Extend16S => ValType::I32,
            I64ExtendI32S | I64ExtendI32U | I64Extend8S | I64Extend16S | I64Extend32S => {
                ValType::I64
            }

            // Float comparisons return i32 (0 or 1)
            F32Eq | F32Ne | F32Lt | F32Gt | F32Le | F32Ge | F64Eq | F64Ne | F64Lt | F64Gt
            | F64Le | F64Ge => ValType::I32,

            // f32 operations return f32
            F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc | F32Nearest | F32Sqrt | F32Add
            | F32Sub | F32Mul | F32Div | F32Min | F32Max | F32Copysign | F32ConvertI32S
            | F32ConvertI32U | F32ConvertI64S | F32ConvertI64U | F32DemoteF64
            | F32ReinterpretI32 => ValType::F32,

            // f64 operations return f64
            F64Abs | F64Neg | F64Ceil | F64Floor | F64Trunc | F64Nearest | F64Sqrt | F64Add
            | F64Sub | F64Mul | F64Div | F64Min | F64Max | F64Copysign | F64ConvertI32S
            | F64ConvertI32U | F64ConvertI64S | F64ConvertI64U | F64PromoteF32
            | F64ReinterpretI64 => ValType::F64,

            // Float truncations to i32
            I32TruncF32S | I32TruncF32U | I32TruncF64S | I32TruncF64U | I32ReinterpretF32
            | I32TruncSatF32S | I32TruncSatF32U | I32TruncSatF64S | I32TruncSatF64U => ValType::I32,

            // Float truncations to i64
            I64TruncF32S | I64TruncF32U | I64TruncF64S | I64TruncF64U | I64ReinterpretF64
            | I64TruncSatF32S | I64TruncSatF32U | I64TruncSatF64S | I64TruncSatF64U => ValType::I64,
        }
    }

    /// Returns the number of operands this instruction consumes.
    pub fn input_arity(&self) -> usize {
        use InstructionArith::*;
        match self {
            // Unary integer operations
            I32Eqz | I64Eqz | I32Clz | I32Ctz | I32Popcnt | I64Clz | I64Ctz | I64Popcnt
            | I32WrapI64 | I64ExtendI32S | I64ExtendI32U | I32Extend8S | I32Extend16S
            | I64Extend8S | I64Extend16S | I64Extend32S => 1,

            // Unary float operations
            F32Abs | F32Neg | F32Ceil | F32Floor | F32Trunc | F32Nearest | F32Sqrt | F64Abs
            | F64Neg | F64Ceil | F64Floor | F64Trunc | F64Nearest | F64Sqrt => 1,

            // Float conversions (all unary)
            I32TruncF32S | I32TruncF32U | I32TruncF64S | I32TruncF64U | I64TruncF32S
            | I64TruncF32U | I64TruncF64S | I64TruncF64U | F32ConvertI32S | F32ConvertI32U
            | F32ConvertI64S | F32ConvertI64U | F64ConvertI32S | F64ConvertI32U
            | F64ConvertI64S | F64ConvertI64U | F32DemoteF64 | F64PromoteF32
            | I32ReinterpretF32 | I64ReinterpretF64 | F32ReinterpretI32 | F64ReinterpretI64
            | I32TruncSatF32S | I32TruncSatF32U | I32TruncSatF64S | I32TruncSatF64U
            | I64TruncSatF32S | I64TruncSatF32U | I64TruncSatF64S | I64TruncSatF64U => 1,

            // Binary operations (everything else)
            _ => 2,
        }
    }

    /// Returns `true` if this is a floating-point instruction.
    pub fn is_float(&self) -> bool {
        use InstructionArith::*;
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
                | F32Abs
                | F32Neg
                | F32Ceil
                | F32Floor
                | F32Trunc
                | F32Nearest
                | F32Sqrt
                | F32Add
                | F32Sub
                | F32Mul
                | F32Div
                | F32Min
                | F32Max
                | F32Copysign
                | F64Abs
                | F64Neg
                | F64Ceil
                | F64Floor
                | F64Trunc
                | F64Nearest
                | F64Sqrt
                | F64Add
                | F64Sub
                | F64Mul
                | F64Div
                | F64Min
                | F64Max
                | F64Copysign
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

/// WebAssembly instructions (integer-only subset).
///
/// This enum represents all supported WebAssembly instructions from the core
/// specification, excluding floating point operations. Each variant corresponds
/// to a WASM instruction with its operands.
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    // Control Flow Instructions
    /// `unreachable`: Trap immediately.
    ///
    /// This instruction causes an unconditional trap.
    Unreachable,

    /// `nop`: Do nothing.
    ///
    /// No-operation instruction that does not modify any state.
    Nop,

    /// `block`: Begin a block with a given type.
    ///
    /// A structured control instruction that creates a label around its body.
    /// The block type specifies the signature of the block.
    Block { blockty: BlockType },

    /// `loop`: Begin a loop with a given type.
    ///
    /// Similar to block, but branches to the start of the loop rather than the
    /// end.
    Loop { blockty: BlockType },

    /// `if`: Begin an if block with a given type.
    ///
    /// Pops an i32 value from the stack; if non-zero, executes the `then`
    /// branch, otherwise executes the `else` branch (if present).
    If { blockty: BlockType },

    /// `else`: Marks the else branch of an if instruction.
    Else,

    /// `end`: Marks the end of a block, loop, if, or function.
    End,

    /// `br`: Unconditional branch to a target label.
    ///
    /// The operand is the relative depth of the target label.
    Br(u32),

    /// `br_if`: Conditional branch to a target label.
    ///
    /// Pops an i32 value; if non-zero, branches to the target label.
    BrIf(u32),

    /// `br_table`: Branch table for multi-way branching.
    ///
    /// Pops an i32 index and branches to the corresponding label in the targets
    /// vector, or to the default label if the index is out of bounds.
    BrTable { targets: Vec<u32>, default: u32 },

    /// `return`: Return from the current function.
    ///
    /// Branches to the end of the function, returning values from the stack.
    Return,

    // Call Instructions
    /// `call`: Call a function by index.
    ///
    /// Invokes the function at the given index.
    Call(u32),

    /// `call_indirect`: Call a function indirectly through a table.
    ///
    /// Pops an i32 table index from the stack and calls the function at that
    /// position in the table, checking that its type matches the expected
    /// type.
    CallIndirect { type_index: u32, table_index: u32 },

    // Parametric Instructions
    /// `drop`: Drop a value from the stack.
    ///
    /// Pops and discards a value from the stack.
    Drop,

    /// `select`: Select one of two values based on a condition.
    ///
    /// Pops an i32 condition and two values; pushes the first value if
    /// condition is non-zero, otherwise pushes the second value.
    Select,

    /// `select t`: Typed select instruction.
    ///
    /// Like select, but with an explicit type annotation.
    SelectTyped(Vec<ValType>),

    // Variable Instructions
    /// `local.get`: Read a local variable.
    ///
    /// Pushes the value of the local variable at the given index onto the
    /// stack.
    LocalGet(u32),

    /// `local.set`: Write a local variable.
    ///
    /// Pops a value from the stack and stores it in the local variable at the
    /// given index.
    LocalSet(u32),

    /// `local.tee`: Write a local variable and return the value.
    ///
    /// Like local.set, but also pushes the value back onto the stack.
    LocalTee(u32),

    /// `global.get`: Read a global variable.
    ///
    /// Pushes the value of the global variable at the given index onto the
    /// stack.
    GlobalGet(u32),

    /// `global.set`: Write a global variable.
    ///
    /// Pops a value from the stack and stores it in the global variable at the
    /// given index. The global must be mutable.
    GlobalSet(u32),

    // Memory Instructions
    /// `i32.load`: Load 4 bytes as i32.
    ///
    /// Loads a 32-bit integer from memory at the address on top of the stack
    /// plus the offset.
    I32Load(MemArg),

    /// `i64.load`: Load 8 bytes as i64.
    ///
    /// Loads a 64-bit integer from memory at the address on top of the stack
    /// plus the offset.
    I64Load(MemArg),

    /// `i32.load8_s`: Load 1 byte and sign-extend to i32.
    I32Load8S(MemArg),

    /// `i32.load8_u`: Load 1 byte and zero-extend to i32.
    I32Load8U(MemArg),

    /// `i32.load16_s`: Load 2 bytes and sign-extend to i32.
    I32Load16S(MemArg),

    /// `i32.load16_u`: Load 2 bytes and zero-extend to i32.
    I32Load16U(MemArg),

    /// `i64.load8_s`: Load 1 byte and sign-extend to i64.
    I64Load8S(MemArg),

    /// `i64.load8_u`: Load 1 byte and zero-extend to i64.
    I64Load8U(MemArg),

    /// `i64.load16_s`: Load 2 bytes and sign-extend to i64.
    I64Load16S(MemArg),

    /// `i64.load16_u`: Load 2 bytes and zero-extend to i64.
    I64Load16U(MemArg),

    /// `i64.load32_s`: Load 4 bytes and sign-extend to i64.
    I64Load32S(MemArg),

    /// `i64.load32_u`: Load 4 bytes and zero-extend to i64.
    I64Load32U(MemArg),

    /// `i32.store`: Store 4 bytes from i32.
    ///
    /// Stores a 32-bit integer to memory at the address on the stack plus the
    /// offset.
    I32Store(MemArg),

    /// `i64.store`: Store 8 bytes from i64.
    ///
    /// Stores a 64-bit integer to memory at the address on the stack plus the
    /// offset.
    I64Store(MemArg),

    /// `i32.store8`: Wrap i32 to i8 and store 1 byte.
    I32Store8(MemArg),

    /// `i32.store16`: Wrap i32 to i16 and store 2 bytes.
    I32Store16(MemArg),

    /// `i64.store8`: Wrap i64 to i8 and store 1 byte.
    I64Store8(MemArg),

    /// `i64.store16`: Wrap i64 to i16 and store 2 bytes.
    I64Store16(MemArg),

    /// `i64.store32`: Wrap i64 to i32 and store 4 bytes.
    I64Store32(MemArg),

    /// `memory.size`: Query the size of memory in pages (64 KiB each).
    ///
    /// Pushes the current memory size onto the stack.
    MemorySize,

    /// `memory.grow`: Grow memory by a given number of pages.
    ///
    /// Pops the number of pages to grow; pushes the previous size or -1 on
    /// failure.
    MemoryGrow,

    /// `memory.fill`: Fill a region of memory with a value.
    ///
    /// Pops destination address, value, and size from stack.
    /// Fills `size` bytes starting at `dest` with `value`.
    MemoryFill,

    /// `memory.copy`: Copy a region of memory.
    ///
    /// Pops destination address, source address, and size from stack.
    /// Copies `size` bytes from `src` to `dest`.
    MemoryCopy,

    /// `memory.init`: Initialize memory from a data segment.
    ///
    /// Pops destination address, source offset, and size from stack.
    /// Copies `size` bytes from data segment to memory.
    MemoryInit(u32),

    /// `data.drop`: Drop a data segment.
    ///
    /// Marks a data segment as no longer needed.
    DataDrop(u32),

    // Numeric Instructions - Constants
    /// `i32.const`: Produce an i32 constant.
    ///
    /// Pushes the given 32-bit integer constant onto the stack.
    I32Const(i32),

    /// `i64.const`: Produce an i64 constant.
    ///
    /// Pushes the given 64-bit integer constant onto the stack.
    I64Const(i64),

    /// `f32.const`: Produce an f32 constant (will trap at runtime).
    F32Const(u32), // Store as bits to avoid float handling

    /// `f64.const`: Produce an f64 constant (will trap at runtime).
    F64Const(u64), // Store as bits to avoid float handling

    // Float memory operations (will trap at runtime)
    /// `f32.load`: Load 4 bytes as f32 (will trap at runtime).
    F32Load(MemArg),
    /// `f64.load`: Load 8 bytes as f64 (will trap at runtime).
    F64Load(MemArg),
    /// `f32.store`: Store f32 to memory (will trap at runtime).
    F32Store(MemArg),
    /// `f64.store`: Store f64 to memory (will trap at runtime).
    F64Store(MemArg),

    // Reference Instructions
    /// `ref.null`: Produce a null reference.
    ///
    /// Pushes a null reference of the given type onto the stack.
    RefNull(RefType),

    /// `ref.is_null`: Test whether a reference is null.
    ///
    /// Pops a reference and pushes 1 if it is null, 0 otherwise.
    RefIsNull,

    /// `ref.func`: Produce a reference to a function.
    ///
    /// Pushes a reference to the function at the given index onto the stack.
    RefFunc(u32),

    /// Arithmetic, comparison, and conversion operations.
    Arith(InstructionArith),
}

impl Instruction {
    /// Returns the input arity of the instruction.
    pub fn input_arity(&self) -> usize {
        use Instruction::*;
        match self {
            // 0 inputs
            Unreachable
            | Nop
            | Block { .. }
            | Loop { .. }
            | Else
            | End
            | Return
            | LocalGet(_)
            | GlobalGet(_)
            | MemorySize
            | I32Const(_)
            | I64Const(_)
            | F32Const(_)
            | F64Const(_)
            | RefNull(_)
            | RefFunc(_)
            | DataDrop(_)
            | Call(_)
            | CallIndirect { .. } => 0,

            // 1 input
            If { .. }
            | Br(_)
            | BrIf(_)
            | BrTable { .. }
            | Drop
            | LocalSet(_)
            | LocalTee(_)
            | GlobalSet(_)
            | I32Load(_)
            | I64Load(_)
            | I32Load8S(_)
            | I32Load8U(_)
            | I32Load16S(_)
            | I32Load16U(_)
            | I64Load8S(_)
            | I64Load8U(_)
            | I64Load16S(_)
            | I64Load16U(_)
            | I64Load32S(_)
            | I64Load32U(_)
            | F32Load(_)
            | F64Load(_)
            | MemoryGrow
            | RefIsNull => 1,

            // 2 inputs
            I32Store(_) | I64Store(_) | I32Store8(_) | I32Store16(_) | I64Store8(_)
            | I64Store16(_) | I64Store32(_) | F32Store(_) | F64Store(_) => 2,

            // 3 inputs
            Select | SelectTyped(_) | MemoryFill | MemoryCopy | MemoryInit(_) => 3,

            // Delegate to operand count
            Arith(op) => op.input_arity(),
        }
    }

    /// Returns the output arity of the instruction.
    pub fn output_arity(&self) -> usize {
        use Instruction::*;
        match self {
            // 0 outputs
            Unreachable
            | Nop
            | Block { .. }
            | Loop { .. }
            | If { .. }
            | Else
            | End
            | Br(_)
            | Return
            | Drop
            | LocalSet(_)
            | GlobalSet(_)
            | I32Store(_)
            | I64Store(_)
            | I32Store8(_)
            | I32Store16(_)
            | I64Store8(_)
            | I64Store16(_)
            | I64Store32(_)
            | F32Store(_)
            | F64Store(_)
            | MemoryFill
            | MemoryCopy
            | MemoryInit(_)
            | DataDrop(_)
            | Call(_)
            | CallIndirect { .. } => 0,

            // 1 output
            BrIf(_)
            | BrTable { .. }
            | Select
            | SelectTyped(_)
            | LocalGet(_)
            | LocalTee(_)
            | GlobalGet(_)
            | I32Load(_)
            | I64Load(_)
            | I32Load8S(_)
            | I32Load8U(_)
            | I32Load16S(_)
            | I32Load16U(_)
            | I64Load8S(_)
            | I64Load8U(_)
            | I64Load16S(_)
            | I64Load16U(_)
            | I64Load32S(_)
            | I64Load32U(_)
            | F32Load(_)
            | F64Load(_)
            | MemorySize
            | MemoryGrow
            | I32Const(_)
            | I64Const(_)
            | F32Const(_)
            | F64Const(_)
            | RefNull(_)
            | RefIsNull
            | RefFunc(_)
            | Arith(_) => 1,
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
