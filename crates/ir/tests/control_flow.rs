use std::collections::HashSet;

use ir::{
    BinaryArith, BinaryOp, BlockId, Function, FunctionBody, Instruction, InstructionArith, Module,
    Terminator,
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

/// Collect all reachable blocks from entry.
fn reachable_blocks(body: &FunctionBody) -> HashSet<usize> {
    let mut visited = HashSet::new();
    let mut stack = vec![body.entry.index()];
    while let Some(idx) = stack.pop() {
        if !visited.insert(idx) {
            continue;
        }
        if idx < body.blocks.len() {
            for target in terminator_targets(&body.blocks[idx].terminator) {
                stack.push(target.index());
            }
        }
    }
    visited
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

#[test]
fn test_basic_block() {
    let module = parse_wat(r#"(func (result i32) (block (result i32) i32.const 42))"#);
    let body = get_func_body(&module, 0);

    assert_eq!(body.entry, BlockId(0));
    // Block 0: i32.const into reg 1, copy to result reg 0, jump to continuation
    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::I32Const { dst: 1, val: 42 }));
    assert!(b0.body.contains(&Instruction::Copy { dst: 0, src: 1 }));
    assert!(matches!(b0.terminator, Terminator::Jump { .. }));

    // Continuation block has return with result reg 0
    assert!(
        body.blocks
            .iter()
            .any(|b| b.terminator == Terminator::Return { values: vec![0] })
    );
}

#[test]
fn test_block_with_br() {
    let module = parse_wat(r#"(func (result i32) (block (result i32) i32.const 42 br 0))"#);
    let body = get_func_body(&module, 0);

    // Block result reg is 0, const goes to reg 1
    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::I32Const { dst: 1, val: 42 }));
    // The br 0 copies to result reg and produces a Jump terminator
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

    // Entry block should have the const and call
    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::I32Const { dst: 0, val: 42 }));
    assert!(b0.body.contains(&Instruction::Call {
        dst: Some(1),
        func_idx: 0,
        args: vec![0]
    }));
    assert!(matches!(b0.terminator, Terminator::Return { .. }));
}

#[test]
fn test_return_with_value() {
    let module = parse_wat(r#"(func (result i32) i32.const 42 return)"#);
    let body = get_func_body(&module, 0);

    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::I32Const { dst: 0, val: 42 }));
    assert_eq!(b0.terminator, Terminator::Return { values: vec![0] });
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

    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::Copy { dst: 1, src: 0 }));
    assert_eq!(b0.terminator, Terminator::Return { values: vec![1] });
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

    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::I32Const { dst: 0, val: 10 }));
    assert!(b0.body.contains(&Instruction::I32Const { dst: 1, val: 20 }));
    assert!(b0.body.contains(&Instruction::Call {
        dst: Some(2),
        func_idx: 0,
        args: vec![0, 1]
    }));
    assert_eq!(b0.terminator, Terminator::Return { values: vec![2] });
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

    let b0 = &body.blocks[0];
    assert!(b0.body.contains(&Instruction::CallIndirect {
        dst: Some(4),
        type_index: 0,
        table_index: 0,
        table_idx: 3,
        args: vec![2],
    }));
    assert!(matches!(b0.terminator, Terminator::Return { .. }));
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
