//! The bundled WebAssembly core spec suites, as raw `.wast` text.

macro_rules! suite {
    ($name:ident, $file:literal) => {
        #[doc = concat!("The `", $file, ".wast` core spec suite.")]
        pub const $name: &str = include_str!(concat!("../spec/", $file, ".wast"));
    };
}

suite!(I32, "i32");
suite!(I64, "i64");
suite!(F32, "f32");
suite!(F64, "f64");
suite!(MEMORY, "memory");
suite!(LOCAL_GET, "local_get");
suite!(LOCAL_SET, "local_set");
suite!(LOCAL_TEE, "local_tee");
suite!(GLOBAL, "global");
suite!(BLOCK, "block");
suite!(LOOP, "loop");
suite!(IF, "if");
suite!(BR, "br");
suite!(BR_IF, "br_if");
suite!(BR_TABLE, "br_table");
suite!(RETURN, "return");
suite!(UNREACHABLE, "unreachable");
suite!(NOP, "nop");
suite!(FUNC, "func");
suite!(CALL, "call");
suite!(CALL_INDIRECT, "call_indirect");
suite!(SELECT, "select");
suite!(DATA, "data");
suite!(ELEM, "elem");
suite!(TABLE, "table");

/// Every bundled suite as `(name, wast)`, for running the whole set in one go.
pub const ALL: &[(&str, &str)] = &[
    ("i32", I32),
    ("i64", I64),
    ("f32", F32),
    ("f64", F64),
    ("memory", MEMORY),
    ("local_get", LOCAL_GET),
    ("local_set", LOCAL_SET),
    ("local_tee", LOCAL_TEE),
    ("global", GLOBAL),
    ("block", BLOCK),
    ("loop", LOOP),
    ("if", IF),
    ("br", BR),
    ("br_if", BR_IF),
    ("br_table", BR_TABLE),
    ("return", RETURN),
    ("unreachable", UNREACHABLE),
    ("nop", NOP),
    ("func", FUNC),
    ("call", CALL),
    ("call_indirect", CALL_INDIRECT),
    ("select", SELECT),
    ("data", DATA),
    ("elem", ELEM),
    ("table", TABLE),
];
