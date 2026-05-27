//! `#[poly_kernel]` — attribute macro that turns a constraint function
//! written against `mpz_circuits_new::Context` into its sibling
//! `impl ProverKernel`, `impl VerifierKernel`, and `ConstraintDef`
//! bundle via the lifter.
//!
//! The macro does not statically interpret arbitrary Rust. Doing so
//! would balloon the AST → IR translator and the macro's surface
//! area for no real gain — real-world constraint bodies stay within a
//! small idiomatic subset.
//!
//! Supported Rust constructs:
//!
//!   - `let` / `let mut` bindings, with reassignment.
//!   - `ctx.{add, sub, mul, constant, assert_const}` calls; `E::zero()` /
//!     `E::one()` recognized as constants.
//!   - Array literals and constant-folded indexing (`vars[2 * i + 1]`).
//!   - Range expressions (`0..N`, `0..=N`) inside `for` / `.map`.
//!   - `for` loops over constant ranges or arrays.
//!   - `.map(|j| …).collect()` with captures of locals, `&mut ctx`, and outer
//!     loop variables.
//!   - Local `fn` definitions + free calls (nested helpers allowed).
//!   - Slice expressions: `arr[i..j]`, `arr[i..=j]`, `arr[..]`, `&arr[i..]`.
//!   - `assert!` macro calls (ignored).
//!
//! Anything else (`if`, `match`, `while`, arbitrary fn calls) emits a
//! span-anchored `syn::Error` at expansion — no silent fallthrough.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, spanned::Spanned};

mod interp;

#[proc_macro_attribute]
pub fn poly_kernel(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(attr with syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated);
    let internal = attr_args.iter().any(|m| match m {
        syn::Meta::Path(p) => p.is_ident("internal"),
        _ => false,
    });
    let input = parse_macro_input!(item as syn::ItemFn);
    match expand(&input, internal) {
        Ok(ts) => ts.into(),
        Err(e) => {
            let err = e.to_compile_error();
            let original = &input;
            quote! {
                #original
                #err
            }
            .into()
        }
    }
}

fn expand(input: &syn::ItemFn, internal: bool) -> syn::Result<TokenStream2> {
    let fn_name = &input.sig.ident;
    let pascal = pascal_case(&fn_name.to_string());
    let kernel_name = format_ident!("{}Kernel", pascal);
    let verifier_kernel_name = format_ident!("{}VerifierKernel", pascal);
    let def_name = format_ident!("{}", pascal);

    // Annotated fns must have exactly two parameters: `ctx: &mut C`
    // and `vars: [C::Wire; N]`. We read `N` here to learn the
    // constraint's arity.
    let num_vars = extract_num_vars(&input.sig)?;

    // Statically interpret the body, build the IR.
    let ir = interp::interpret_fn(input, num_vars)?;
    let degree = ir.nodes[ir.output.unwrap().0].degree;

    // Pull kernel impl sources out of the lifter, then re-parse them
    // as TokenStream2 so we can splice them in.
    //
    // `internal` switches the trait/bound references from the default
    // absolute (`::mpz_poly_proof_core::...`) to `crate::...` — needed
    // when the macro is applied inside `mpz-poly-proof-core` itself,
    // which can't refer to itself by its external name without
    // `extern crate self`.
    let paths = if internal {
        mpz_poly_proof_lifter::Paths {
            kernel: "crate::kernel::ProverKernel".into(),
            verifier_kernel: "crate::kernel::VerifierKernel".into(),
            constraint_def: "crate::kernel::ConstraintDef".into(),
            extension_field: "crate::ExtensionField".into(),
            field: "crate::Field".into(),
        }
    } else {
        mpz_poly_proof_lifter::Paths::default()
    };

    let parse = |src: String, what: &str| -> syn::Result<TokenStream2> {
        src.parse().map_err(|e: proc_macro2::LexError| {
            syn::Error::new(
                input.sig.ident.span(),
                format!("emitted {what} did not parse: {e}"),
            )
        })
    };

    let kernel_ts = parse(
        mpz_poly_proof_lifter::emit_prover(&kernel_name.to_string(), &ir, &paths),
        "ProverKernel impl",
    )?;
    let verifier_ts = parse(
        mpz_poly_proof_lifter::emit_verifier(&verifier_kernel_name.to_string(), &ir, &paths),
        "VerifierKernel impl",
    )?;
    let def_ts = parse(
        mpz_poly_proof_lifter::emit_constraint_def(
            &def_name.to_string(),
            &kernel_name.to_string(),
            &verifier_kernel_name.to_string(),
            &ir,
            &paths,
        ),
        "ConstraintDef impl",
    )?;
    // `degree` and `num_vars` are no longer read directly — they
    // round-trip through the lifter's IR + `emit_constraint_def`.
    let _ = (num_vars, degree);

    // Emit the original fn unchanged + prover kernel + verifier
    // kernel + ConstraintDef bundle.
    Ok(quote! {
        #input

        #kernel_ts

        #verifier_ts

        #def_ts
    })
}

/// Find `vars: [_; N]` in the function signature and return `N`.
fn extract_num_vars(sig: &syn::Signature) -> syn::Result<usize> {
    // We expect the second parameter (after `ctx`) to be `vars: [...; N]`.
    let vars_pat = sig.inputs.iter().nth(1).ok_or_else(|| {
        syn::Error::new(
            sig.span(),
            "expected at least two parameters: `ctx: &mut C` and `vars: [C::Wire; N]`",
        )
    })?;
    let pt = match vars_pat {
        syn::FnArg::Typed(pt) => pt,
        syn::FnArg::Receiver(_) => {
            return Err(syn::Error::new(
                vars_pat.span(),
                "expected a typed parameter for `vars`",
            ));
        }
    };
    let arr = match &*pt.ty {
        syn::Type::Array(a) => a,
        other => {
            return Err(syn::Error::new(
                other.span(),
                "expected `vars: [_; N]` as the second parameter",
            ));
        }
    };
    // `arr.len` is a syn::Expr representing N. We expect a literal usize.
    let n_lit = match &arr.len {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(li),
            ..
        }) => li.base10_parse::<usize>()?,
        other => {
            return Err(syn::Error::new(
                other.span(),
                "expected the array length N to be an integer literal",
            ));
        }
    };
    Ok(n_lit)
}

/// `mul_force` → `MulForce`. Identifier-only segments, no
/// punctuation handling.
fn pascal_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper_next = true;
    for ch in snake.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}
