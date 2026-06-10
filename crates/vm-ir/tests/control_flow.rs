use mpz_vm_ir::{
    BinaryArith, BinaryOp, BlockId, Function, FunctionBody, Instruction, InstructionArith, Module,
    Reg, Terminator,
};

fn parse_wat(wat: &str) -> Module {
    let full_wat = format!("(module {})", wat);
    let binary = wat::parse_str(&full_wat).expect("valid WAT");
    Module::parse(&binary).expect("valid module")
}

/// Validate that all terminator targets point to valid block indices.
fn validate_cfg(body: &FunctionBody) {
    let num_blocks = body.blocks.len();
    assert!(
        body.entry.index() < num_blocks,
        "entry {:?} out of range (have {} blocks)",
        body.entry,
        num_blocks
    );

    for (i, block) in body.blocks.iter().enumerate() {
        let targets = terminator_targets(&block.terminator);
        for target in &targets {
            assert!(
                target.index() < num_blocks,
                "block {} terminator targets {:?} but only {} blocks exist",
                i,
                target,
                num_blocks
            );
        }
    }
}

fn terminator_targets(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::Jump { target } => vec![*target],
        Terminator::BrCond {
            then_target,
            else_target,
            ..
        } => vec![*then_target, *else_target],
        Terminator::BrTable {
            targets, default, ..
        } => {
            let mut v = targets.clone();
            v.push(*default);
            v
        }
        Terminator::Return { .. } | Terminator::Unreachable => vec![],
    }
}

fn get_func_body(module: &Module, idx: usize) -> &FunctionBody {
    match &module.functions()[idx] {
        Function::Local(f) => f.body(),
        _ => panic!("expected local function"),
    }
}

/// Find the single `Call` instruction in a block, if any.
fn find_call(block: &mpz_vm_ir::BasicBlock) -> Option<&Instruction> {
    block
        .body
        .iter()
        .find(|i| matches!(i, Instruction::Call { .. }))
}

/// Find the single `CallIndirect` instruction in a block, if any.
fn find_call_indirect(block: &mpz_vm_ir::BasicBlock) -> Option<&Instruction> {
    block
        .body
        .iter()
        .find(|i| matches!(i, Instruction::CallIndirect { .. }))
}

/// Collect the destination register of the const writing `val` (i32), if
/// present.
fn i32_const_dst(block: &mpz_vm_ir::BasicBlock, val: i32) -> Option<Reg> {
    block.body.iter().find_map(|i| match i {
        Instruction::I32Const { dst, val: v } if *v == val => Some(*dst),
        _ => None,
    })
}

/// Returns the set of registers returned by the (assumed single) `Return`
/// terminator reachable from the entry block of this body.
fn return_values(body: &FunctionBody) -> Vec<Reg> {
    body.blocks
        .iter()
        .find_map(|b| match &b.terminator {
            Terminator::Return { values } => Some(values.clone()),
            _ => None,
        })
        .expect("body should have a Return terminator")
}

#[test]
fn test_basic_block() {
    let module = parse_wat(r#"(func (result i32) (block (result i32) i32.const 42))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);

    assert_eq!(body.entry, BlockId(0));
    // Block 0 produces the const and jumps to the block's continuation. The
    // exact register feeding the continuation is an allocation detail; assert
    // the structure (const present, Jump terminator) instead.
    let b0 = &body.blocks[0];
    assert!(
        i32_const_dst(b0, 42).is_some(),
        "i32.const 42 should be present"
    );
    assert!(matches!(b0.terminator, Terminator::Jump { .. }));

    // The block's result is carried through to a Return.
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. })),
        "should have a Return terminator"
    );
    assert_eq!(return_values(body).len(), 1, "should return one value");
}

#[test]
fn test_block_with_br() {
    let module = parse_wat(r#"(func (result i32) (block (result i32) i32.const 42 br 0))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);

    // The const is produced, and `br 0` exits the block with a Jump. Register
    // numbers are an allocation detail.
    let b0 = &body.blocks[0];
    assert!(
        i32_const_dst(b0, 42).is_some(),
        "i32.const 42 should be present"
    );
    assert!(matches!(b0.terminator, Terminator::Jump { .. }));
}

#[test]
fn test_if_then_else() {
    let module = parse_wat(
        r#"(func (param i32) (result i32) (if (result i32) (local.get 0) (then (i32.const 1)) (else (i32.const 0))))"#,
    );
    let body = get_func_body(&module, 0);

    // Should have a BrCond terminator for the if
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::BrCond { .. }))
    );

    // Should have a Return terminator
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. }))
    );

    // Then and else blocks should have const instructions
    let has_const_1 = body.blocks.iter().any(|b| {
        b.body
            .iter()
            .any(|i| matches!(i, Instruction::I32Const { val: 1, .. }))
    });
    let has_const_0 = body.blocks.iter().any(|b| {
        b.body
            .iter()
            .any(|i| matches!(i, Instruction::I32Const { val: 0, .. }))
    });
    assert!(has_const_1);
    assert!(has_const_0);
}

#[test]
fn test_call_with_args() {
    let module = parse_wat(
        r#"(func $callee (param i32) (result i32) (local.get 0)) (func (result i32) i32.const 42 call $callee)"#,
    );
    let body = get_func_body(&module, 1);
    validate_cfg(body);

    // Entry block should produce the const, then call func 0 with that const as
    // its sole argument and a destination register. Register numbers are an
    // allocation detail; assert the data-flow instead: the const's dst is the
    // call's only arg, and the call's result is what the function returns.
    let b0 = &body.blocks[0];
    let const_dst = i32_const_dst(b0, 42).expect("i32.const 42 should be present");

    let call = find_call(b0).expect("a Call should be present");
    let Instruction::Call {
        dst,
        func_idx,
        args,
    } = call
    else {
        unreachable!()
    };
    assert_eq!(*func_idx, 0);
    assert_eq!(args, &vec![const_dst], "call arg should be the const's reg");
    let call_dst = dst.expect("call to a value-returning func should have a dst");

    assert!(matches!(b0.terminator, Terminator::Return { .. }));
    assert_eq!(
        return_values(body),
        vec![call_dst],
        "function should return the call result"
    );
}

#[test]
fn test_return_with_value() {
    let module = parse_wat(r#"(func (result i32) i32.const 42 return)"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);

    // The const's register is exactly what `return` carries; assert that
    // data-flow rather than hard-coding the register number.
    let b0 = &body.blocks[0];
    let const_dst = i32_const_dst(b0, 42).expect("i32.const 42 should be present");
    assert_eq!(
        b0.terminator,
        Terminator::Return {
            values: vec![const_dst]
        }
    );
}

#[test]
fn test_void_function() {
    let module = parse_wat(r#"(func nop)"#);
    let body = get_func_body(&module, 0);

    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::Nop));
    assert_eq!(b0.terminator, Terminator::Return { values: vec![] });
}

#[test]
fn test_i64_identity() {
    let module = parse_wat(r#"(func (param i64) (result i64) local.get 0)"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);

    // An identity function returns its sole parameter. `local.get` aliases the
    // param's register directly, so the body may legitimately be empty (no
    // Copy). The observable property is that the function returns exactly one
    // value, and that value is the parameter register (reg 0).
    let returned = return_values(body);
    assert_eq!(
        returned,
        vec![Reg(0)],
        "should return the param register unchanged"
    );
}

#[test]
fn test_br_if_with_value() {
    let module = parse_wat(
        r#"(func (param i32) (result i32) (block (result i32) i32.const 42 local.get 0 br_if 0 drop i32.const 0))"#,
    );
    let body = get_func_body(&module, 0);

    // Should have a BrCond terminator for the br_if
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::BrCond { .. }))
    );

    // Should have a Return terminator
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. }))
    );
}

#[test]
fn test_br_table() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (block (result i32)
                (block (result i32)
                    (block (result i32)
                        i32.const 100
                        local.get 0
                        br_table 0 1 2
                    )
                )
            )
        )"#,
    );
    let body = get_func_body(&module, 0);

    // Should have a BrTable terminator
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::BrTable { .. }))
    );
}

#[test]
fn test_loop_continue() {
    let module = parse_wat(
        r#"(func (param i32) (result i32) (local i32) i32.const 0 local.set 1 (block (result i32) (loop local.get 0 local.get 1 i32.add local.set 1 local.get 1 i32.const 100 i32.lt_s br_if 0) local.get 1))"#,
    );
    let body = get_func_body(&module, 0);

    // Should have a BrCond (from br_if) that targets the loop header
    let br_cond_block = body
        .blocks
        .iter()
        .find(|b| matches!(b.terminator, Terminator::BrCond { .. }));
    assert!(br_cond_block.is_some());

    // Should have a Return
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. }))
    );

    // The loop body should contain the add instruction
    assert!(body.blocks.iter().any(|b| b.body.iter().any(|i| matches!(
        i,
        Instruction::Arith(InstructionArith::Binary(BinaryArith {
            op: BinaryOp::I32Add,
            ..
        }))
    ))));
}

#[test]
fn test_unreachable() {
    let module = parse_wat(r#"(func unreachable)"#);
    let body = get_func_body(&module, 0);

    // Entry block should have Unreachable terminator
    let b0 = &body.blocks[0];
    assert_eq!(b0.terminator, Terminator::Unreachable);
}

#[test]
fn test_multi_arg_call() {
    let module = parse_wat(
        r#"(func $add (param i32 i32) (result i32) local.get 0 local.get 1 i32.add) (func (result i32) i32.const 10 i32.const 20 call $add)"#,
    );
    let body = get_func_body(&module, 1);
    validate_cfg(body);

    // Two consts feed the two call args in order; the call result is returned.
    // Register numbers are an allocation detail, so check the data-flow.
    let b0 = &body.blocks[0];
    let c10 = i32_const_dst(b0, 10).expect("i32.const 10 should be present");
    let c20 = i32_const_dst(b0, 20).expect("i32.const 20 should be present");

    let call = find_call(b0).expect("a Call should be present");
    let Instruction::Call {
        dst,
        func_idx,
        args,
    } = call
    else {
        unreachable!()
    };
    assert_eq!(*func_idx, 0);
    assert_eq!(
        args,
        &vec![c10, c20],
        "call args should be the two const regs in order"
    );
    let call_dst = dst.expect("call to a value-returning func should have a dst");

    assert_eq!(
        return_values(body),
        vec![call_dst],
        "function should return the call result"
    );
}

#[test]
fn test_nested_blocks_with_br() {
    let module = parse_wat(
        r#"(func (result i32) (block (result i32) (block i32.const 42 br 1) i32.const 0))"#,
    );
    let body = get_func_body(&module, 0);

    // Should have a block with i32.const 42 followed by a Jump (br 1)
    // Outer block result reg is 0, inner block has no result, const goes to reg 1
    let has_42 = body.blocks.iter().any(|b| {
        b.body
            .iter()
            .any(|i| matches!(i, Instruction::I32Const { val: 42, .. }))
            && matches!(b.terminator, Terminator::Jump { .. })
    });
    assert!(has_42);

    // Should have a Return
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. }))
    );
}

#[test]
fn test_if_with_nested_block() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (if (result i32) (local.get 0)
                (then (block (result i32) (i32.const 42)))
                (else (i32.const 0))
            )
        )"#,
    );
    let body = get_func_body(&module, 0);

    // Should have BrCond for the if
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::BrCond { .. }))
    );

    // Should have the constants (register numbers may vary due to result reg
    // allocation)
    assert!(body.blocks.iter().any(|b| {
        b.body
            .iter()
            .any(|i| matches!(i, Instruction::I32Const { val: 42, .. }))
    }));
    assert!(body.blocks.iter().any(|b| {
        b.body
            .iter()
            .any(|i| matches!(i, Instruction::I32Const { val: 0, .. }))
    }));

    // Should have Return
    assert!(
        body.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Return { .. }))
    );
}

#[test]
fn test_call_indirect_i64() {
    let module = parse_wat(
        r#"(type $t (func (param i64) (result i64))) (table funcref (elem $id)) (func $id (param i64) (result i64) (local.get 0)) (func (param i32 i64) (result i64) local.get 1 local.get 0 call_indirect (type $t))"#,
    );
    let body = get_func_body(&module, 1);
    validate_cfg(body);

    // The caller has params i32 (reg 0) and i64 (reg 1). `local.get 1` pushes
    // the call argument and `local.get 0` pushes the table index; both alias
    // their param registers directly. Assert the structural facts (type/table
    // indices, arity, result returned) and the data-flow (table_idx is the i32
    // param, the sole arg is the i64 param) rather than exact register numbers.
    let b0 = &body.blocks[0];
    let call = find_call_indirect(b0).expect("a CallIndirect should be present");
    let Instruction::CallIndirect {
        dst,
        type_index,
        table_index,
        table_idx,
        args,
    } = call
    else {
        unreachable!()
    };
    assert_eq!(*type_index, 0);
    assert_eq!(*table_index, 0);
    assert_eq!(
        *table_idx,
        Reg(0),
        "table index operand is the i32 param (reg 0)"
    );
    assert_eq!(args, &vec![Reg(1)], "call arg is the i64 param (reg 1)");
    let call_dst = dst.expect("call to a value-returning type should have a dst");

    assert!(matches!(b0.terminator, Terminator::Return { .. }));
    assert_eq!(
        return_values(body),
        vec![call_dst],
        "function should return the call result"
    );
}

// ============================================================
// CFG validation tests
// ============================================================

#[test]
fn test_cfg_valid_empty_func() {
    let module = parse_wat(r#"(func)"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_block() {
    let module = parse_wat(r#"(func (block nop))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_if_no_else() {
    let module = parse_wat(r#"(func (param i32) (if (local.get 0) (then nop)))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_if_else() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (if (result i32) (local.get 0) (then i32.const 1) (else i32.const 2)))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_loop() {
    let module = parse_wat(r#"(func (param i32) (loop local.get 0 br_if 0))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_nested_if() {
    let module = parse_wat(
        r#"(func (param i32 i32) (result i32)
            (if (result i32) (local.get 0)
                (then (if (result i32) (local.get 1) (then i32.const 1) (else i32.const 2)))
                (else i32.const 3)))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
    let br_count = body
        .blocks
        .iter()
        .filter(|b| matches!(b.terminator, Terminator::BrCond { .. }))
        .count();
    assert!(br_count >= 2, "expected 2+ BrCond, got {}", br_count);
}

#[test]
fn test_cfg_valid_br_if_fallthrough() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (block (result i32) i32.const 42 local.get 0 br_if 0 drop i32.const 0))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_br_table() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (block (result i32) (block (result i32) i32.const 99 local.get 0 br_table 0 1)))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_loop_with_block_exit() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (block (result i32) (loop i32.const 42 br 1) i32.const 0))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_unreachable_after_br() {
    let module =
        parse_wat(r#"(func (result i32) (block (result i32) i32.const 42 br 0 i32.const 99))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_valid_unreachable_after_return() {
    let module = parse_wat(r#"(func (result i32) i32.const 42 return i32.const 99)"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_br_if_type_i32() {
    // This pattern was hanging in spec_runner
    let module =
        parse_wat(r#"(func (block (drop (i32.ctz (br_if 0 (i32.const 0) (i32.const 1))))))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_br_if_in_loop_depth1() {
    // br_if 1 inside a loop should target the OUTER block, not the loop header
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (block (loop (br_if 1 (local.get 0)) (return (i32.const 2)))) (i32.const 3)
        )"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_br_if_value() {
    let module = parse_wat(
        r#"(func (result i32)
            (block (result i32) (i32.ctz (br_if 0 (i32.const 1) (i32.const 1)))))"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_if_without_else_no_result() {
    let module = parse_wat(r#"(func (param i32) (if (local.get 0) (then nop)))"#);
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}

#[test]
fn test_cfg_select_single_block() {
    let module = parse_wat(
        r#"(func (param i32 i32 i32) (result i32) local.get 0 local.get 1 local.get 2 select)"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
    assert_eq!(body.blocks.len(), 1);
}

#[test]
fn test_cfg_multiple_returns() {
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            local.get 0
            if (result i32) i32.const 1 return else i32.const 2 return end)"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
    let return_count = body
        .blocks
        .iter()
        .filter(|b| matches!(b.terminator, Terminator::Return { .. }))
        .count();
    assert!(
        return_count >= 2,
        "expected 2+ Returns, got {}",
        return_count
    );
}

#[test]
fn test_cfg_loop_counter() {
    // Classic loop counting pattern
    let module = parse_wat(
        r#"(func (param i32) (result i32)
            (local i32)
            i32.const 0
            local.set 1
            (block $exit (result i32)
                (loop $loop
                    local.get 1
                    i32.const 1
                    i32.add
                    local.set 1
                    local.get 1
                    local.get 0
                    i32.lt_s
                    br_if $loop
                )
                local.get 1
            )
        )"#,
    );
    let body = get_func_body(&module, 0);
    validate_cfg(body);
}
