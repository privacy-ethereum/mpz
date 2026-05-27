//! AST interpreter for the Context-DSL subset.
//!
//! Walks a constraint function body and builds an
//! [`mpz_poly_proof_lifter::Ir`] symbolically.

use std::collections::HashMap;

use mpz_poly_proof_lifter::{ConstVal, Ir, NodeHandle};
use syn::{Expr, ExprMethodCall, ExprPath, ItemFn, Pat, RangeLimits, Stmt, UnOp, spanned::Spanned};

/// Symbolic value.
#[derive(Debug, Clone)]
enum Val {
    /// Wire-valued: an IR node handle.
    Wire(NodeHandle),
    /// Array of values (used for `vars`, slices, and `.collect()` outputs).
    Array(Vec<Val>),
    /// Compile-time integer (loop indices, constant offsets).
    Int(usize),
    /// Statement result, `Result::Ok(())`, etc.
    Unit,
}

struct Interp {
    ir: Ir,
    scopes: Vec<HashMap<String, Val>>,
    local_fns: HashMap<String, ItemFn>,
}

impl Interp {
    fn new() -> Self {
        Self {
            ir: Ir::new(),
            scopes: vec![HashMap::new()],
            local_fns: HashMap::new(),
        }
    }

    fn lookup(&self, name: &str) -> Option<Val> {
        for scope in self.scopes.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Some(v.clone());
            }
        }
        None
    }

    fn bind(&mut self, name: String, val: Val) {
        self.scopes.last_mut().unwrap().insert(name, val);
    }

    /// Rebind in the innermost scope that already has `name`; else
    /// bind in the innermost. Used for `x = …;` assignments.
    fn rebind(&mut self, name: &str, val: Val) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), val);
                return;
            }
        }
        // Fallback: bind in innermost (shouldn't typically happen for
        // a well-typed program — but it's harmless).
        self.scopes
            .last_mut()
            .unwrap()
            .insert(name.to_string(), val);
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
}

pub fn interpret_fn(input: &ItemFn, num_vars: usize) -> syn::Result<Ir> {
    let mut interp = Interp::new();

    let var_pat_name = extract_vars_param_name(&input.sig)?;
    let vars: Vec<Val> = (0..num_vars)
        .map(|i| Val::Wire(interp.ir.op_var(i)))
        .collect();
    interp.bind(var_pat_name, Val::Array(vars));

    interp.eval_block(&input.block)?;

    if interp.ir.output.is_none() {
        return Err(syn::Error::new(
            input.sig.ident.span(),
            "constraint did not call `ctx.assert_const(_, E::zero())` — \
             the lifter requires exactly one such assertion as the final statement",
        ));
    }
    Ok(interp.ir)
}

fn extract_vars_param_name(sig: &syn::Signature) -> syn::Result<String> {
    let vars_pat = sig
        .inputs
        .iter()
        .nth(1)
        .ok_or_else(|| syn::Error::new(sig.span(), "missing `vars` parameter"))?;
    let pt = match vars_pat {
        syn::FnArg::Typed(pt) => pt,
        _ => return Err(syn::Error::new(vars_pat.span(), "expected typed parameter")),
    };
    match &*pt.pat {
        syn::Pat::Ident(pi) => Ok(pi.ident.to_string()),
        other => Err(syn::Error::new(
            other.span(),
            "expected `vars` parameter to be a simple identifier",
        )),
    }
}

impl Interp {
    // ---------------------------------------------------------------
    // Statements
    // ---------------------------------------------------------------

    fn eval_block(&mut self, block: &syn::Block) -> syn::Result<Val> {
        // Two-pass: register local fn items first so call-sites can
        // appear anywhere in the block, then evaluate statements.
        for stmt in &block.stmts {
            if let Stmt::Item(syn::Item::Fn(item_fn)) = stmt {
                self.local_fns
                    .insert(item_fn.sig.ident.to_string(), item_fn.clone());
            }
        }
        let mut last = Val::Unit;
        for (i, stmt) in block.stmts.iter().enumerate() {
            let is_last = i + 1 == block.stmts.len();
            last = self.eval_stmt(stmt, is_last)?;
        }
        Ok(last)
    }

    fn eval_stmt(&mut self, stmt: &Stmt, _is_last: bool) -> syn::Result<Val> {
        match stmt {
            Stmt::Local(local) => {
                let init = local
                    .init
                    .as_ref()
                    .ok_or_else(|| syn::Error::new(local.span(), "`let` without initializer"))?;
                if init.diverge.is_some() {
                    return Err(syn::Error::new(
                        init.expr.span(),
                        "`let-else` is not supported",
                    ));
                }
                let val = self.eval_expr(&init.expr)?;
                self.bind_pat(&local.pat, val)?;
                Ok(Val::Unit)
            }
            Stmt::Expr(expr, _semi) => self.eval_expr(expr),
            Stmt::Item(syn::Item::Fn(_)) => {
                // Already registered in `eval_block`'s first pass.
                Ok(Val::Unit)
            }
            Stmt::Item(item) => Err(syn::Error::new(
                item.span(),
                "items other than nested `fn` are not supported",
            )),
            Stmt::Macro(m) => {
                // `assert!`, `assert_eq!`, `debug_assert!`, etc. — runtime
                // checks; ignore at trace time. Anything else: error.
                let path = m.mac.path.get_ident().map(|i| i.to_string());
                match path.as_deref() {
                    Some(
                        "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq"
                        | "debug_assert_ne",
                    ) => Ok(Val::Unit),
                    _ => Err(syn::Error::new(
                        m.span(),
                        "unsupported macro call in constraint body",
                    )),
                }
            }
        }
    }

    fn bind_pat(&mut self, pat: &Pat, val: Val) -> syn::Result<()> {
        match pat {
            Pat::Ident(pi) => {
                if pi.subpat.is_some() {
                    return Err(syn::Error::new(
                        pi.span(),
                        "sub-patterns in `let` not supported",
                    ));
                }
                self.bind(pi.ident.to_string(), val);
                Ok(())
            }
            Pat::Wild(_) => Ok(()),
            Pat::Reference(pr) => {
                // `&n` / `&mut n` — strip the reference layer.
                self.bind_pat(&pr.pat, val)
            }
            Pat::Type(pt) => self.bind_pat(&pt.pat, val),
            Pat::Tuple(_) | Pat::TupleStruct(_) => Err(syn::Error::new(
                pat.span(),
                "tuple-destructuring patterns not yet supported",
            )),
            other => Err(syn::Error::new(
                other.span(),
                "only ident, ref-ident, type-annotated ident, or `_` patterns supported in `let`",
            )),
        }
    }

    // ---------------------------------------------------------------
    // Expressions
    // ---------------------------------------------------------------

    fn eval_expr(&mut self, expr: &Expr) -> syn::Result<Val> {
        match expr {
            Expr::Path(p) => self.eval_path(p),
            Expr::Lit(l) => self.eval_literal(l),
            Expr::Index(idx) => self.eval_index(idx),
            Expr::MethodCall(m) => self.eval_method_call(m),
            Expr::Call(c) => self.eval_call(c),
            Expr::Paren(p) => self.eval_expr(&p.expr),
            Expr::Reference(r) => self.eval_expr(&r.expr),
            Expr::Block(b) => self.eval_block(&b.block),
            Expr::Array(a) => {
                let elts: syn::Result<Vec<Val>> =
                    a.elems.iter().map(|e| self.eval_expr(e)).collect();
                Ok(Val::Array(elts?))
            }
            Expr::Binary(b) => self.eval_binary(b),
            Expr::Unary(u) => self.eval_unary(u),
            Expr::ForLoop(f) => self.eval_for(f),
            Expr::Assign(a) => self.eval_assign(a),
            Expr::Cast(c) => {
                // Ignore the cast type — values are dynamically typed at
                // interp time. Eval inner.
                self.eval_expr(&c.expr)
            }
            Expr::Range(_) => Err(syn::Error::new(
                expr.span(),
                "range expressions are only allowed as the iterator in a `for` loop, \
                 the receiver of `.map`, or inside an index `arr[i..j]`",
            )),
            Expr::Closure(_) => Err(syn::Error::new(
                expr.span(),
                "closures are only allowed as the argument to `.map(|...| ...)` in phase 2",
            )),
            other => Err(syn::Error::new(
                other.span(),
                "unsupported expression in constraint body",
            )),
        }
    }

    fn eval_literal(&self, l: &syn::ExprLit) -> syn::Result<Val> {
        match &l.lit {
            syn::Lit::Int(li) => Ok(Val::Int(li.base10_parse::<usize>()?)),
            _ => Err(syn::Error::new(
                l.span(),
                "only integer literals are supported as values",
            )),
        }
    }

    fn eval_path(&self, p: &ExprPath) -> syn::Result<Val> {
        if p.path.segments.len() == 1 && p.qself.is_none() {
            let name = p.path.segments[0].ident.to_string();
            return self
                .lookup(&name)
                .ok_or_else(|| syn::Error::new(p.span(), format!("unknown identifier `{name}`")));
        }
        Err(syn::Error::new(
            p.span(),
            "qualified paths are only allowed inside `ctx.constant(...)` / `ctx.assert_const(...)` \
             as `E::zero()` / `E::one()`",
        ))
    }

    fn eval_index(&mut self, idx: &syn::ExprIndex) -> syn::Result<Val> {
        let arr_val = self.eval_expr(&idx.expr)?;
        let arr = match arr_val {
            Val::Array(v) => v,
            _ => {
                return Err(syn::Error::new(
                    idx.expr.span(),
                    "indexing into a non-array value",
                ));
            }
        };
        // Index expression: either an integer or a range.
        if let Expr::Range(r) = &*idx.index {
            let (start, end) = self.eval_range_bounds(r, arr.len())?;
            return Ok(Val::Array(arr[start..end].to_vec()));
        }
        let n = self.eval_to_int(&idx.index)?;
        arr.get(n).cloned().ok_or_else(|| {
            syn::Error::new(
                idx.span(),
                format!("index {n} out of bounds (len {})", arr.len()),
            )
        })
    }

    /// Evaluate a range's bounds as `(start, end)` half-open. Uses
    /// `default_len` as the upper bound when the range omits its
    /// `end`. Constants only.
    fn eval_range_bounds(
        &mut self,
        r: &syn::ExprRange,
        default_len: usize,
    ) -> syn::Result<(usize, usize)> {
        let start = match r.start.as_deref() {
            Some(e) => self.eval_to_int(e)?,
            None => 0,
        };
        let end_inclusive = matches!(r.limits, RangeLimits::Closed(_));
        let end_raw = match r.end.as_deref() {
            Some(e) => self.eval_to_int(e)?,
            None => default_len,
        };
        let end = if end_inclusive { end_raw + 1 } else { end_raw };
        Ok((start, end))
    }

    fn eval_to_int(&mut self, expr: &Expr) -> syn::Result<usize> {
        match self.eval_expr(expr)? {
            Val::Int(n) => Ok(n),
            other => Err(syn::Error::new(
                expr.span(),
                format!("expected a compile-time integer, got {other:?}"),
            )),
        }
    }

    fn eval_binary(&mut self, b: &syn::ExprBinary) -> syn::Result<Val> {
        let l = self.eval_expr(&b.left)?;
        let r = self.eval_expr(&b.right)?;
        match (l, r) {
            (Val::Int(li), Val::Int(ri)) => {
                let v = match b.op {
                    syn::BinOp::Add(_) => li + ri,
                    syn::BinOp::Sub(_) => li.checked_sub(ri).ok_or_else(|| {
                        syn::Error::new(b.span(), "integer underflow in constant arithmetic")
                    })?,
                    syn::BinOp::Mul(_) => li * ri,
                    syn::BinOp::Div(_) => li / ri,
                    syn::BinOp::Rem(_) => li % ri,
                    _ => {
                        return Err(syn::Error::new(
                            b.span(),
                            "unsupported integer binary operator",
                        ));
                    }
                };
                Ok(Val::Int(v))
            }
            _ => Err(syn::Error::new(
                b.span(),
                "binary operators only supported on integer values (compile-time arithmetic)",
            )),
        }
    }

    fn eval_unary(&mut self, u: &syn::ExprUnary) -> syn::Result<Val> {
        // `-int` not supported (we'd need signed ints); `*x` (deref) /
        // `!x` are unsupported in phase 2.
        Err(syn::Error::new(
            u.span(),
            match u.op {
                UnOp::Neg(_) => "negation not supported (no signed integers in interpreter)",
                UnOp::Not(_) => "logical-not not supported",
                UnOp::Deref(_) => "deref `*x` not supported",
                _ => "unsupported unary operator",
            },
        ))
    }

    fn eval_assign(&mut self, a: &syn::ExprAssign) -> syn::Result<Val> {
        let name = match &*a.left {
            Expr::Path(p) if p.path.segments.len() == 1 && p.qself.is_none() => {
                p.path.segments[0].ident.to_string()
            }
            other => {
                return Err(syn::Error::new(
                    other.span(),
                    "only assignments to a single identifier are supported (`name = …`)",
                ));
            }
        };
        let val = self.eval_expr(&a.right)?;
        self.rebind(&name, val);
        Ok(Val::Unit)
    }

    fn eval_for(&mut self, f: &syn::ExprForLoop) -> syn::Result<Val> {
        let items = self.eval_iter(&f.expr, 0)?;
        for v in items {
            self.push_scope();
            let bind = self.bind_pat(&f.pat, v);
            let r = bind.and_then(|()| self.eval_block(&f.body));
            self.pop_scope();
            r?;
        }
        Ok(Val::Unit)
    }

    /// Evaluate an iterator-shaped expression to a sequence of `Val`s.
    /// Supports `range`, `range.iter()`/`.into_iter()` (transparent),
    /// and any expression that evaluates to `Val::Array`.
    /// `default_len` is used as the implicit end of an unbounded range
    /// — irrelevant for ranges used by `for`/`map`, which always have
    /// both bounds.
    fn eval_iter(&mut self, expr: &Expr, _default_len: usize) -> syn::Result<Vec<Val>> {
        // Peel `(…)` so `(0..16).map(...)` is treated as `0..16`.
        let mut inner = expr;
        while let Expr::Paren(p) = inner {
            inner = &p.expr;
        }
        match inner {
            Expr::Range(r) => {
                let (start, end) = self.eval_range_bounds(r, 0)?;
                Ok((start..end).map(Val::Int).collect())
            }
            _ => match self.eval_expr(inner)? {
                Val::Array(v) => Ok(v),
                other => Err(syn::Error::new(
                    expr.span(),
                    format!("cannot iterate over value of kind {other:?}"),
                )),
            },
        }
    }

    // ---------------------------------------------------------------
    // Method-call dispatch (`ctx.METHOD`, `.map`, `.collect`)
    // ---------------------------------------------------------------

    fn eval_method_call(&mut self, m: &ExprMethodCall) -> syn::Result<Val> {
        let method = m.method.to_string();

        // Ctx-side methods: dispatch directly (the receiver is the
        // `ctx` argument; we don't track it as a Val).
        match method.as_str() {
            "add" => {
                let (a, b) = two_args(m)?;
                let aw = self.eval_to_wire(a)?;
                let bw = self.eval_to_wire(b)?;
                return Ok(Val::Wire(self.ir.op_add(aw, bw)));
            }
            "sub" => {
                // Mirror `KernelEmitter::sub`: lower `a - b` to
                // `a + (-b)` so the static IR matches the runtime IR.
                let (a, b) = two_args(m)?;
                let aw = self.eval_to_wire(a)?;
                let bw = self.eval_to_wire(b)?;
                let neg_bw = self.ir.op_neg(bw);
                return Ok(Val::Wire(self.ir.op_add(aw, neg_bw)));
            }
            "mul" => {
                let (a, b) = two_args(m)?;
                let aw = self.eval_to_wire(a)?;
                let bw = self.eval_to_wire(b)?;
                return Ok(Val::Wire(self.ir.op_mul(aw, bw)));
            }
            "constant" => {
                let v = one_arg(m)?;
                let cv = self.eval_field_const(v)?;
                let h = match cv {
                    ConstVal::Zero => self.ir.op_const_zero(),
                    ConstVal::One => self.ir.op_const_one(),
                };
                return Ok(Val::Wire(h));
            }
            "assert_const" => {
                let (v, expected) = two_args(m)?;
                let cv = self.eval_field_const(expected)?;
                if cv != ConstVal::Zero {
                    return Err(syn::Error::new(
                        expected.span(),
                        "the lifter requires `assert_const(_, E::zero())`",
                    ));
                }
                let w = self.eval_to_wire(v)?;
                self.ir.set_output(w);
                return Ok(Val::Unit);
            }
            _ => {}
        }

        // Non-ctx methods: handle `.map(closure)`, `.collect()`,
        // `.iter()`/`.into_iter()` (transparent).
        match method.as_str() {
            "map" => {
                let closure_expr = one_arg(m)?;
                let closure = match closure_expr {
                    Expr::Closure(c) => c,
                    _ => {
                        return Err(syn::Error::new(
                            closure_expr.span(),
                            "`.map(...)` argument must be a closure literal",
                        ));
                    }
                };
                let items = self.eval_iter(&m.receiver, 0)?;
                let mapped: syn::Result<Vec<Val>> = items
                    .into_iter()
                    .map(|elem| self.call_closure(closure, elem))
                    .collect();
                Ok(Val::Array(mapped?))
            }
            "collect" => {
                // `.collect::<Vec<_>>()` after `.map(...)` — the map
                // already produced a Val::Array, so collect is a no-op.
                if !m.args.is_empty() {
                    return Err(syn::Error::new(m.span(), "`.collect()` takes no args"));
                }
                self.eval_expr(&m.receiver)
            }
            "iter" | "into_iter" => {
                if !m.args.is_empty() {
                    return Err(syn::Error::new(m.span(), "`.iter()` takes no args"));
                }
                // Transparent: pass through the receiver value.
                self.eval_expr(&m.receiver)
            }
            other => Err(syn::Error::new(
                m.method.span(),
                format!("unsupported method `.{other}(...)` in phase 2"),
            )),
        }
    }

    fn call_closure(&mut self, closure: &syn::ExprClosure, arg: Val) -> syn::Result<Val> {
        if closure.inputs.len() != 1 {
            return Err(syn::Error::new(
                closure.span(),
                "closures with exactly one parameter are supported in phase 2",
            ));
        }
        self.push_scope();
        let bind = self.bind_pat(&closure.inputs[0], arg);
        let r = bind.and_then(|()| self.eval_expr(&closure.body));
        self.pop_scope();
        r
    }

    // ---------------------------------------------------------------
    // Free function call (look up in `local_fns`, inline)
    // ---------------------------------------------------------------

    fn eval_call(&mut self, c: &syn::ExprCall) -> syn::Result<Val> {
        let fn_name = match &*c.func {
            Expr::Path(p) if p.path.segments.len() == 1 && p.qself.is_none() => {
                p.path.segments[0].ident.to_string()
            }
            _ => {
                return Err(syn::Error::new(
                    c.func.span(),
                    "function calls must be to a locally-defined `fn` by name",
                ));
            }
        };
        let item_fn = self
            .local_fns
            .get(&fn_name)
            .cloned()
            .ok_or_else(|| {
                syn::Error::new(
                    c.func.span(),
                    format!(
                        "unknown function `{fn_name}` — only local `fn` defs inside the constraint body are callable"
                    ),
                )
            })?;

        // Bind each arg to the corresponding sig parameter.
        // The first sig parameter is typically `ctx` (or `&mut C`),
        // which we don't track as a Val. We skip it in the params,
        // and skip the matching argument too.
        let sig_params: Vec<&syn::PatType> = item_fn
            .sig
            .inputs
            .iter()
            .filter_map(|fa| {
                if let syn::FnArg::Typed(pt) = fa {
                    Some(pt)
                } else {
                    None
                }
            })
            .collect();
        // Identify the `ctx` parameter: the first one whose type is a
        // `&mut C`-shape (Reference to a path with no further
        // qualification). Heuristic, but matches our fixtures.
        let ctx_idx = sig_params.iter().position(|pt| is_ctx_typed(&pt.ty));
        let ctx_param_idx = ctx_idx.unwrap_or(0);

        let nontrivial_params: Vec<&syn::PatType> = sig_params
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, _)| *i != ctx_param_idx)
            .map(|(_, p)| p)
            .collect();
        let call_args: Vec<&Expr> = c
            .args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != ctx_param_idx)
            .map(|(_, a)| a)
            .collect();
        if nontrivial_params.len() != call_args.len() {
            return Err(syn::Error::new(
                c.span(),
                format!(
                    "function `{fn_name}` expects {} non-ctx arguments, got {}",
                    nontrivial_params.len(),
                    call_args.len()
                ),
            ));
        }

        // Evaluate each argument under the *caller's* scope (closure-
        // capture semantics for whatever the caller had bound).
        let arg_vals: syn::Result<Vec<Val>> = call_args.iter().map(|a| self.eval_expr(a)).collect();
        let arg_vals = arg_vals?;

        // Inline-execute the function body with a fresh scope stack
        // (functions are not closures; they don't see the caller's
        // locals). Bind each non-ctx parameter, then run the body.
        let saved_scopes = std::mem::take(&mut self.scopes);
        let saved_local_fns = self.local_fns.clone();
        self.scopes = vec![HashMap::new()];
        for (param, val) in nontrivial_params.iter().zip(arg_vals) {
            self.bind_pat(&param.pat, val)?;
        }
        // Register any nested fn defs inside the body, then run.
        let result = self.eval_block(&item_fn.block);
        self.scopes = saved_scopes;
        self.local_fns = saved_local_fns;
        result
    }

    // ---------------------------------------------------------------
    // Shared helpers (E::zero / E::one, wire coercion)
    // ---------------------------------------------------------------

    fn eval_to_wire(&mut self, expr: &Expr) -> syn::Result<NodeHandle> {
        match self.eval_expr(expr)? {
            Val::Wire(h) => Ok(h),
            Val::Unit => Err(syn::Error::new(
                expr.span(),
                "expected a wire-valued expression, got `()`",
            )),
            Val::Array(_) => Err(syn::Error::new(
                expr.span(),
                "expected a wire-valued expression, got an array",
            )),
            Val::Int(_) => Err(syn::Error::new(
                expr.span(),
                "expected a wire-valued expression, got a compile-time integer",
            )),
        }
    }

    fn eval_field_const(&self, expr: &Expr) -> syn::Result<ConstVal> {
        let call = match expr {
            Expr::Call(c) => c,
            _ => {
                return Err(syn::Error::new(
                    expr.span(),
                    "expected `E::zero()` or `E::one()`",
                ));
            }
        };
        if !call.args.is_empty() {
            return Err(syn::Error::new(
                expr.span(),
                "expected zero-argument call `E::zero()` / `E::one()`",
            ));
        }
        let path = match &*call.func {
            Expr::Path(p) => &p.path,
            _ => {
                return Err(syn::Error::new(
                    call.func.span(),
                    "expected a path callee `…::zero` / `…::one`",
                ));
            }
        };
        let last = path
            .segments
            .last()
            .ok_or_else(|| syn::Error::new(path.span(), "empty path inside `ctx.constant`"))?;
        match last.ident.to_string().as_str() {
            "zero" => Ok(ConstVal::Zero),
            "one" => Ok(ConstVal::One),
            other => Err(syn::Error::new(
                last.ident.span(),
                format!("expected `zero` or `one`, got `{other}`"),
            )),
        }
    }
}

fn one_arg(m: &ExprMethodCall) -> syn::Result<&Expr> {
    if m.args.len() != 1 {
        return Err(syn::Error::new(
            m.span(),
            format!("expected 1 argument, found {}", m.args.len()),
        ));
    }
    Ok(&m.args[0])
}

fn two_args(m: &ExprMethodCall) -> syn::Result<(&Expr, &Expr)> {
    if m.args.len() != 2 {
        return Err(syn::Error::new(
            m.span(),
            format!("expected 2 arguments, found {}", m.args.len()),
        ));
    }
    Ok((&m.args[0], &m.args[1]))
}

/// Heuristic: does this type look like `&mut C` (the constraint's
/// Context-typed parameter)?
fn is_ctx_typed(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Reference(r) if r.mutability.is_some())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Static-IR vs runtime-IR equivalence.
    //!
    //! Builds the IR two ways from the same constraint fn:
    //!
    //!   * **Static**: parse the fn source via `syn`, run [`interpret_fn`].
    //!   * **Runtime**: call the fn via
    //!     [`mpz_poly_proof_lifter::trace_constraint`], which records every
    //!     `Context` method call into an `Ir`.
    //!
    //! These must be **structurally identical** — same nodes in the same
    //! order with the same operands, degrees, and slot kinds. If they
    //! diverge, the static interpreter disagrees with the runtime tracer
    //! (the trusted oracle).
    //!
    //! One combined constraint exercises every Rust pattern the interpreter
    //! supports — including the trickier interactions (helpers calling
    //! helpers, nested loops, `.map` inside `for`, closures capturing loop
    //! variables). Inline `// pattern: …` comments mark each construct so a
    //! failure (which dumps both IRs in full) can be read against the
    //! constraint body to pinpoint a regression.

    use mpz_circuits_new::Context;
    use mpz_fields::{Field, gf2::Gf2, gf2_64::Gf2_64};
    use mpz_poly_proof_lifter::{LifterError, trace_constraint};

    use crate::interp::interpret_fn;

    // Single constraint covering every pattern. `vars` layout:
    //
    //   vars[0]      Y (constraint root)
    //   vars[1..9]   two 2x2 grids: vars[1..5] (first) + vars[5..9] (second)
    //   vars[9..12]  three extras consumed by the `.map`-in-`for` section
    //                and the cross-product helper call.
    // The fixture deliberately includes `assert!(true, ..)` to prove the
    // interpreter ignores `assert!`; allow the resulting const-assert lint.
    #[allow(clippy::assertions_on_constants)]
    fn combined_patterns<C, E>(ctx: &mut C, vars: [C::Wire; 12]) -> Result<(), C::Error>
    where
        C: Context<Field = E>,
        E: Field,
    {
        // pattern: `assert!` macro — runtime check, ignored by the static
        // interpreter; runtime tracer just executes it. The literal-`true`
        // is the point of the pattern (see the fn-level allow).
        assert!(true, "ignored by both interpreters");

        // pattern: local `fn` definition inside the constraint body.
        fn add_all<C: Context>(ctx: &mut C, xs: &[C::Wire]) -> C::Wire {
            // pattern: indexing a slice by a literal (`xs[0]`).
            let mut acc = xs[0];
            // pattern: `for &x in &xs[1..]` — slice iteration with
            // leading-element skip via range slicing.
            for &x in &xs[1..] {
                // pattern: `ctx.add` method call.
                acc = ctx.add(acc, x);
            }
            acc
        }

        // pattern: second local fn that *itself* calls a local fn
        // (`add_all`). Static interp must inline `cross_product`'s body
        // and then inline each `add_all` call inside.
        fn cross_product<C: Context>(ctx: &mut C, a: &[C::Wire], b: &[C::Wire]) -> C::Wire {
            let sa = add_all(ctx, a);
            let sb = add_all(ctx, b);
            // pattern: `ctx.mul` returning the multiplied result.
            ctx.mul(sa, sb)
        }

        let y = vars[0];

        // pattern: `ctx.constant(E::one())` — recognized as Op::Const(One)
        // by the static interp; the runtime tracer pushes the same node.
        let one = ctx.constant(E::one());

        // pattern: nested `for` loops. Inner loop body uses *both* loop
        // variables in a computed index `1 + 2 * i + j`, exercising the
        // interp's constant-folder for multi-variable index expressions.
        // pattern: `let mut` + reassignment of `grid_sum` inside the outer
        // loop (and across both loop bodies).
        let mut grid_sum = one;
        for i in 0..2 {
            for j in 0..2 {
                // pattern: `ctx.mul` with operands at computed indices
                // depending on two enclosing-scope loop variables.
                let p = ctx.mul(vars[1 + 2 * i + j], vars[5 + 2 * i + j]);
                grid_sum = ctx.add(grid_sum, p);
            }
        }

        // pattern: `.map(|j| …).collect()` *nested inside* a `for k` loop.
        // The closure captures `&mut ctx` and the outer loop variable
        // `k`, indexing `vars` with `k` and `j` together. The static
        // interp must (a) re-evaluate the map body fresh per outer
        // iteration and (b) substitute the current value of `k` for each
        // inner `j`.
        let mut chain = y;
        for k in 0..2 {
            // pattern: `.collect::<Vec<C::Wire>>()` from a `Range::map`
            // call. Closure body uses `ctx.sub` with computed indices
            // mixing both `k` and `j`.
            let row: Vec<C::Wire> = (0..2)
                .map(|j| ctx.sub(vars[9 + j], vars[5 + k * 2 + j]))
                .collect();
            // pattern: passing a `Vec<C::Wire>` slice across an fn
            // boundary into the `add_all` helper.
            let row_sum = add_all(ctx, &row);
            chain = ctx.add(chain, row_sum);
        }

        // pattern: helper-calling-helper. `cross_product` calls `add_all`
        // twice with two different slice arguments derived from range-
        // based array slicing.
        let cross = cross_product(ctx, &vars[1..3], &vars[9..12]);

        // pattern: chained `ctx.add` / `ctx.sub` combining everything.
        // `ctx.sub` lowers to `Op::Add(_, Op::Neg(_))` on both paths;
        // a regression to the GF(2)-only shortcut would diverge here.
        let combined = ctx.add(grid_sum, chain);
        let final_val = ctx.sub(combined, cross);
        let out = ctx.add(y, final_val);

        // pattern: `ctx.assert_const(_, E::zero())` as the constraint
        // root — binds the IR's `output` handle.
        ctx.assert_const(out, E::zero())
    }

    #[test]
    fn static_ir_equals_runtime_ir_for_combined_patterns() {
        // Static path: parse the fn from source, run the AST interpreter.
        let src = stringify!(
            fn combined_patterns<C, E>(ctx: &mut C, vars: [C::Wire; 12]) -> Result<(), C::Error>
            where
                C: Context<Field = E>,
                E: Field,
            {
                assert!(true, "ignored by both interpreters");

                fn add_all<C: Context>(ctx: &mut C, xs: &[C::Wire]) -> C::Wire {
                    let mut acc = xs[0];
                    for &x in &xs[1..] {
                        acc = ctx.add(acc, x);
                    }
                    acc
                }

                fn cross_product<C: Context>(ctx: &mut C, a: &[C::Wire], b: &[C::Wire]) -> C::Wire {
                    let sa = add_all(ctx, a);
                    let sb = add_all(ctx, b);
                    ctx.mul(sa, sb)
                }

                let y = vars[0];
                let one = ctx.constant(E::one());

                let mut grid_sum = one;
                for i in 0..2 {
                    for j in 0..2 {
                        let p = ctx.mul(vars[1 + 2 * i + j], vars[5 + 2 * i + j]);
                        grid_sum = ctx.add(grid_sum, p);
                    }
                }

                let mut chain = y;
                for k in 0..2 {
                    let row: Vec<C::Wire> = (0..2)
                        .map(|j| ctx.sub(vars[9 + j], vars[5 + k * 2 + j]))
                        .collect();
                    let row_sum = add_all(ctx, &row);
                    chain = ctx.add(chain, row_sum);
                }

                let cross = cross_product(ctx, &vars[1..3], &vars[9..12]);

                let combined = ctx.add(grid_sum, chain);
                let final_val = ctx.sub(combined, cross);
                let out = ctx.add(y, final_val);
                ctx.assert_const(out, E::zero())
            }
        );
        let item_fn: syn::ItemFn = syn::parse_str(src).expect("test fn must parse");
        let static_ir = interpret_fn(&item_fn, 12).expect("static interpreter must succeed");

        // Runtime path: trace the actual fn through `KernelEmitter`.
        let runtime_ir = trace_constraint::<Gf2_64, Gf2, _, 12>(|ctx, vars| {
            combined_patterns(ctx, vars).map_err(|_| LifterError::NoConstraint)
        })
        .expect("runtime tracer must succeed");

        assert_eq!(
            static_ir, runtime_ir,
            "static IR != runtime IR\n\nstatic:  {:#?}\n\nruntime: {:#?}",
            static_ir, runtime_ir,
        );
    }
}
