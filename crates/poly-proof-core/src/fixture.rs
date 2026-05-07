//! Circuit fixtures from the CPU step circuit polynomial.

use crate::{
    Field,
    circuit::{Circuit, CircuitBuilder, NodeId},
};

/// Build all step circuit constraint templates as factored circuits.
///
/// Returns `(circuits, instantiation_counts)` where `instantiation_counts[i]`
/// is how many times template `i` is instantiated per step.
pub fn step_circuit_polynomials<E: Field>() -> (Vec<Circuit<E>>, Vec<usize>) {
    let circuits = vec![
        carry_generate(),     // 0
        carry_chain(),        // 1
        write_back(),         // 2
        write_back_bit0(),    // 3
        addr_base_mux(),      // 4
        addr_index_mux(),     // 5
        mul_bit_extraction(), // 6
        mul_force(),          // 7
        acc_mux(),            // 8
        pc_mux(),             // 9
        sp_mux(),             // 10
        fp_mux(),             // 11
    ];

    let counts = vec![
        32, // carry generate
        32, // carry chain
        31, // write-back i>0
        1,  // write-back i=0
        20, // addr base mux (2 slots x 10 bits)
        32, // addr index mux (2 slots x 16 bits)
        1,  // MUL bit extraction (5-level binary tree)
        1,  // MUL force
        32, // acc' MUX
        20, // PC' MUX (~16 bits + carry)
        12, // SP' MUX (~10 bits + carry)
        18, // FP' MUX
    ];

    (circuits, counts)
}

/// Helper: chain-add multiple nodes. `add_all(cb, &[a, b, c])` = `a + b + c`.
fn add_all<E: Field>(cb: &mut CircuitBuilder<E>, nodes: &[NodeId]) -> NodeId {
    assert!(!nodes.is_empty());
    let mut acc = nodes[0];
    for &n in &nodes[1..] {
        acc = cb.add(acc, n);
    }
    acc
}

// ---------------------------------------------------------------------------
// Template 1: Carry Generate (x32, deg 3, 2 mults)
// ---------------------------------------------------------------------------

/// `Y + (a + c)·(bf + c) = 0`. Vars: Y=0, a=1, b=2, c=3, f=4.
fn carry_generate<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let a = cb.var(1);
    let b = cb.var(2);
    let c = cb.var(3);
    let f = cb.var(4);

    let bf = cb.mul(b, f); // mult 1
    let _lhs = cb.add(a, c); // mult 2
    let _rhs = cb.add(bf, c);
    let product = cb.mul(_lhs, _rhs);
    let out = cb.add(y, product);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 2: Carry Chain (x32, deg 2, 1 mult)
// ---------------------------------------------------------------------------

/// `Y + (g + c)·e = 0`. Vars: Y=0, g=1, c=2, e=3.
fn carry_chain<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let g = cb.var(1);
    let c = cb.var(2);
    let e = cb.var(3);

    let _tmp = cb.add(g, c); // mult 1
    let product = cb.mul(_tmp, e);
    let out = cb.add(y, product);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 3: Write-Back i>0 (x31, deg 6, 5 mults)
// ---------------------------------------------------------------------------

/// ```text
/// chain = g + v + q·(g + a + bf + c)
/// alu   = chain + h·(chain + B)
/// Y     = o + w·(o + alu + s·alu)
/// ```
///
/// Constraint: `Y + o + w·(o + alu + s·alu) = 0`.
///
/// Vars: Y=0, o=1, w=2, s=3, q=4, v=5, h=6, B=7, g=8, a=9, b=10, c=11, f=12.
fn write_back<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let o = cb.var(1);
    let w = cb.var(2);
    let s = cb.var(3);
    let q = cb.var(4);
    let v = cb.var(5);
    let h = cb.var(6);
    let big_b = cb.var(7);
    let g = cb.var(8);
    let a = cb.var(9);
    let b = cb.var(10);
    let c = cb.var(11);
    let f = cb.var(12);

    let bf = cb.mul(b, f); // mult 1
    let _sum = add_all(&mut cb, &[g, a, bf, c]);
    let q_inner = cb.mul(q, _sum); // mult 2
    let chain = add_all(&mut cb, &[g, v, q_inner]);
    let _tmp = cb.add(chain, big_b); // mult 3
    let h_term = cb.mul(h, _tmp);
    let alu = cb.add(chain, h_term);
    let s_alu = cb.mul(s, alu); // mult 4
    let _sum = add_all(&mut cb, &[o, alu, s_alu]);
    let w_inner = cb.mul(w, _sum); // mult 5
    let out = add_all(&mut cb, &[y, o, w_inner]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 4: Write-Back i=0 (x1, deg 6, 5 mults)
// ---------------------------------------------------------------------------

/// Same as write-back i>0 but absorbs carry flag K:
/// `Y = o + w·(o + alu + s·(alu + K))`.
///
/// Vars: Y=0, o=1, w=2, s=3, q=4, v=5, h=6, B=7, g=8, a=9, b=10, c=11, f=12,
/// K=13.
fn write_back_bit0<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let o = cb.var(1);
    let w = cb.var(2);
    let s = cb.var(3);
    let q = cb.var(4);
    let v = cb.var(5);
    let h = cb.var(6);
    let big_b = cb.var(7);
    let g = cb.var(8);
    let a = cb.var(9);
    let b = cb.var(10);
    let c = cb.var(11);
    let f = cb.var(12);
    let k_carry = cb.var(13);

    let bf = cb.mul(b, f); // mult 1
    let _sum = add_all(&mut cb, &[g, a, bf, c]);
    let q_inner = cb.mul(q, _sum); // mult 2
    let chain = add_all(&mut cb, &[g, v, q_inner]);
    let _tmp = cb.add(chain, big_b); // mult 3
    let h_term = cb.mul(h, _tmp);
    let alu = cb.add(chain, h_term);
    let _tmp = cb.add(alu, k_carry); // mult 4
    let s_term = cb.mul(s, _tmp);
    let _sum = add_all(&mut cb, &[o, alu, s_term]);
    let w_inner = cb.mul(w, _sum); // mult 5
    let out = add_all(&mut cb, &[y, o, w_inner]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 5: Address Base MUX (x20, deg 3, 3 mults)
// ---------------------------------------------------------------------------

/// Two-level binary MUX:
/// ```text
/// P = A + m0·(A + B)
/// Q = C + m0·C
/// Y = P + m1·(P + Q)
/// ```
///
/// Vars: Y=0, A=1, B=2, C=3, m0=4, m1=5.
fn addr_base_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let big_a = cb.var(1);
    let big_b = cb.var(2);
    let big_c = cb.var(3);
    let m0 = cb.var(4);
    let m1 = cb.var(5);

    let _tmp = cb.add(big_a, big_b); // mult 1
    let m0_ab = cb.mul(m0, _tmp);
    let p = cb.add(big_a, m0_ab);
    let m0_c = cb.mul(m0, big_c); // mult 2
    let q = cb.add(big_c, m0_c);
    let _tmp = cb.add(p, q); // mult 3
    let m1_pq = cb.mul(m1, _tmp);
    let p_mux = cb.add(p, m1_pq);
    let out = cb.add(y, p_mux);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 6: Address Index MUX (x32, deg 2, 1 mult)
// ---------------------------------------------------------------------------

/// `Y + B + d·(A + B) = 0`. Vars: Y=0, A=1, B=2, d=3.
fn addr_index_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let a = cb.var(1);
    let b = cb.var(2);
    let d = cb.var(3);

    let _tmp = cb.add(a, b); // mult 1
    let d_ab = cb.mul(d, _tmp);
    let out = add_all(&mut cb, &[y, b, d_ab]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 7: MUL Bit Extraction Tree (x1, deg 6, 31 mults)
// ---------------------------------------------------------------------------

/// 5-level binary tree MUX. Each node: `M = A + s·(A + B)`.
///
/// Vars: Y=0, s0=1, s1=2, s2=3, s3=4, s4=5, x0=6..x31=37.
fn mul_bit_extraction<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let s: Vec<NodeId> = (1..=5).map(|i| cb.var(i)).collect();
    let x: Vec<NodeId> = (0..32).map(|i| cb.var(6 + i)).collect();

    // Helper: 2-to-1 MUX node `a + sel·(a + b)`.
    let mux = |cb: &mut CircuitBuilder<E>, sel: NodeId, a: NodeId, b: NodeId| -> NodeId {
        let diff = cb.add(a, b);
        let term = cb.mul(sel, diff);
        cb.add(a, term)
    };

    // Level 0 (s0): 16 nodes.
    let m0: Vec<NodeId> = (0..16)
        .map(|j| mux(&mut cb, s[0], x[2 * j], x[2 * j + 1]))
        .collect();

    // Level 1 (s1): 8 nodes.
    let m1: Vec<NodeId> = (0..8)
        .map(|j| mux(&mut cb, s[1], m0[2 * j], m0[2 * j + 1]))
        .collect();

    // Level 2 (s2): 4 nodes.
    let m2: Vec<NodeId> = (0..4)
        .map(|j| mux(&mut cb, s[2], m1[2 * j], m1[2 * j + 1]))
        .collect();

    // Level 3 (s3): 2 nodes.
    let m3: Vec<NodeId> = (0..2)
        .map(|j| mux(&mut cb, s[3], m2[2 * j], m2[2 * j + 1]))
        .collect();

    // Level 4 (s4): 1 node → result.
    let result = mux(&mut cb, s[4], m3[0], m3[1]);

    let out = cb.add(y, result);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 8: MUL Force (x1, deg 2, 1 mult)
// ---------------------------------------------------------------------------

/// `Y + 1 + M·(1 + m) = 0`. Vars: Y=0, M=1, m=2.
fn mul_force<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let big_m = cb.var(1);
    let m = cb.var(2);

    let one = cb.constant(E::one());
    let _tmp = cb.add(one, m); // mult 1
    let product = cb.mul(big_m, _tmp);
    let out = add_all(&mut cb, &[y, one, product]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 9: acc' MUX (x32, deg 3, 2 mults)
// ---------------------------------------------------------------------------

/// Don't-care (u0=1, u1=1) allows nesting:
/// ```text
/// R = u0·(W + A)
/// Y = A + R + u1·(S + A + R)
/// ```
///
/// Vars: Y=0, A=1, W=2, S=3, u0=4, u1=5.
fn acc_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let a = cb.var(1);
    let w = cb.var(2);
    let s = cb.var(3);
    let u0 = cb.var(4);
    let u1 = cb.var(5);

    let _tmp = cb.add(w, a); // mult 1
    let r = cb.mul(u0, _tmp);
    let _sum = add_all(&mut cb, &[s, a, r]);
    let u1_term = cb.mul(u1, _sum); // mult 2
    let out = add_all(&mut cb, &[y, a, r, u1_term]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 10: PC' MUX (~20 inst, deg 4, 4 mults)
// ---------------------------------------------------------------------------

/// ```text
/// P = PC + iota
/// D = S + P
/// E = R + P
/// Y = P + p0·D + p1·(k·D + p0·(D + k·D + E))
/// ```
///
/// Vars: Y=0, PC=1, iota=2, S=3, R=4, p0=5, p1=6, k=7.
fn pc_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let pc = cb.var(1);
    let iota = cb.var(2);
    let s = cb.var(3);
    let r = cb.var(4);
    let p0 = cb.var(5);
    let p1 = cb.var(6);
    let k = cb.var(7);

    let p = cb.add(pc, iota);
    let d = cb.add(s, p);
    let e = cb.add(r, p);

    let kd = cb.mul(k, d); // mult 1
    let p0_d = cb.mul(p0, d); // mult 2
    let _sum = add_all(&mut cb, &[d, kd, e]);
    let p0_inner = cb.mul(p0, _sum); // mult 3
    let _tmp = cb.add(kd, p0_inner); // mult 4
    let p1_term = cb.mul(p1, _tmp);
    let out = add_all(&mut cb, &[y, p, p0_d, p1_term]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 11: SP' MUX (~12 inst, deg 3, 2 mults)
// ---------------------------------------------------------------------------

/// Don't-care (r0=1, r1=1) allows nesting:
/// ```text
/// R = r0·D_inc
/// Y = SP + R + r1·(D_dec + R)
/// ```
///
/// Vars: Y=0, SP=1, D_inc=2, D_dec=3, r0=4, r1=5.
fn sp_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let sp = cb.var(1);
    let d_inc = cb.var(2);
    let d_dec = cb.var(3);
    let r0 = cb.var(4);
    let r1 = cb.var(5);

    let r = cb.mul(r0, d_inc); // mult 1
    let _tmp = cb.add(d_dec, r); // mult 2
    let r1_term = cb.mul(r1, _tmp);
    let out = add_all(&mut cb, &[y, sp, r, r1_term]);
    cb.build(out)
}

// ---------------------------------------------------------------------------
// Template 12: FP' MUX (x18, deg 2, 1 mult)
// ---------------------------------------------------------------------------

/// `Y + F + t·(N + F) = 0`. Vars: Y=0, F=1, N=2, t=3.
fn fp_mux<E: Field>() -> Circuit<E> {
    let mut cb = CircuitBuilder::new();
    let y = cb.var(0);
    let f = cb.var(1);
    let n = cb.var(2);
    let t = cb.var(3);

    let _tmp = cb.add(n, f); // mult 1
    let t_nf = cb.mul(t, _tmp);
    let out = add_all(&mut cb, &[y, f, t_nf]);
    cb.build(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_fields::gf2_64::Gf2_64;

    #[test]
    fn test_fixture_stats() {
        let (circuits, counts): (Vec<Circuit<Gf2_64>>, _) = step_circuit_polynomials();

        assert_eq!(circuits.len(), 12);
        assert_eq!(counts.len(), 12);

        let expected: Vec<(usize, usize)> = vec![
            // (degree, mul_count)
            (3, 2),  // carry generate
            (2, 1),  // carry chain
            (6, 5),  // write-back i>0
            (6, 5),  // write-back i=0
            (3, 3),  // addr base mux
            (2, 1),  // addr index mux
            (6, 31), // MUL bit extraction tree
            (2, 1),  // MUL force
            (3, 2),  // acc' MUX
            (4, 4),  // PC' MUX
            (3, 2),  // SP' MUX
            (2, 1),  // FP' MUX
        ];

        for (i, ((exp_deg, exp_muls), circ)) in expected.iter().zip(circuits.iter()).enumerate() {
            assert_eq!(circ.degree(), *exp_deg, "template {i}: degree mismatch");
            assert_eq!(
                circ.mul_count(),
                *exp_muls,
                "template {i}: mul count mismatch"
            );
        }

        // Total instantiations: 232.
        let total: usize = counts.iter().sum();
        assert_eq!(total, 232);
    }
}
