//! Test-only circuit fixtures for downstream crates.

use mpz_fields::Field;

use crate::Context;

/// Helper: chain-add multiple wires. `add_all(ctx, &[a, b, c])` = `a + b + c`.
fn add_all<C: Context>(ctx: &mut C, nodes: &[C::Wire]) -> C::Wire {
    assert!(!nodes.is_empty());
    let mut acc = nodes[0];
    for &n in &nodes[1..] {
        acc = ctx.add(acc, n);
    }
    acc
}

// ===========================================================================
// BEGIN: CPU step circuit emulation (12 constraint templates)
// ===========================================================================

/// `Y + (a + c)·(bf + c) = 0`. Vars: Y=0, a=1, b=2, c=3, f=4.
pub fn carry_generate<C, E>(ctx: &mut C, vars: [C::Wire; 5]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let a = vars[1];
    let b = vars[2];
    let c = vars[3];
    let f = vars[4];

    let bf = ctx.mul(b, f); // mult 1
    let lhs = ctx.add(a, c); // mult 2
    let rhs = ctx.add(bf, c);
    let product = ctx.mul(lhs, rhs);
    let out = ctx.add(y, product);
    ctx.assert_const(out, E::zero())
}

/// `Y + (g + c)·e = 0`. Vars: Y=0, g=1, c=2, e=3.
pub fn carry_chain<C, E>(ctx: &mut C, vars: [C::Wire; 4]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let g = vars[1];
    let c = vars[2];
    let e = vars[3];

    let tmp = ctx.add(g, c); // mult 1
    let product = ctx.mul(tmp, e);
    let out = ctx.add(y, product);
    ctx.assert_const(out, E::zero())
}

/// ```text
/// chain = g + v + q·(g + a + bf + c)
/// alu   = chain + h·(chain + B)
/// Y     = o + w·(o + alu + s·alu)
/// ```
///
/// Constraint: `Y + o + w·(o + alu + s·alu) = 0`.
///
/// Vars: Y=0, o=1, w=2, s=3, q=4, v=5, h=6, B=7, g=8, a=9, b=10, c=11, f=12.
pub fn write_back<C, E>(ctx: &mut C, vars: [C::Wire; 13]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let o = vars[1];
    let w = vars[2];
    let s = vars[3];
    let q = vars[4];
    let v = vars[5];
    let h = vars[6];
    let big_b = vars[7];
    let g = vars[8];
    let a = vars[9];
    let b = vars[10];
    let c = vars[11];
    let f = vars[12];

    let bf = ctx.mul(b, f); // mult 1
    let sum1 = add_all(ctx, &[g, a, bf, c]);
    let q_inner = ctx.mul(q, sum1); // mult 2
    let chain = add_all(ctx, &[g, v, q_inner]);
    let tmp = ctx.add(chain, big_b); // mult 3
    let h_term = ctx.mul(h, tmp);
    let alu = ctx.add(chain, h_term);
    let s_alu = ctx.mul(s, alu); // mult 4
    let sum2 = add_all(ctx, &[o, alu, s_alu]);
    let w_inner = ctx.mul(w, sum2); // mult 5
    let out = add_all(ctx, &[y, o, w_inner]);
    ctx.assert_const(out, E::zero())
}

/// Same as [`write_back`] but absorbs carry flag K:
/// `Y = o + w·(o + alu + s·(alu + K))`.
///
/// Vars: Y=0, o=1, w=2, s=3, q=4, v=5, h=6, B=7, g=8, a=9, b=10, c=11, f=12,
/// K=13.
pub fn write_back_bit0<C, E>(ctx: &mut C, vars: [C::Wire; 14]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let o = vars[1];
    let w = vars[2];
    let s = vars[3];
    let q = vars[4];
    let v = vars[5];
    let h = vars[6];
    let big_b = vars[7];
    let g = vars[8];
    let a = vars[9];
    let b = vars[10];
    let c = vars[11];
    let f = vars[12];
    let k_carry = vars[13];

    let bf = ctx.mul(b, f); // mult 1
    let sum1 = add_all(ctx, &[g, a, bf, c]);
    let q_inner = ctx.mul(q, sum1); // mult 2
    let chain = add_all(ctx, &[g, v, q_inner]);
    let tmp1 = ctx.add(chain, big_b); // mult 3
    let h_term = ctx.mul(h, tmp1);
    let alu = ctx.add(chain, h_term);
    let tmp2 = ctx.add(alu, k_carry); // mult 4
    let s_term = ctx.mul(s, tmp2);
    let sum2 = add_all(ctx, &[o, alu, s_term]);
    let w_inner = ctx.mul(w, sum2); // mult 5
    let out = add_all(ctx, &[y, o, w_inner]);
    ctx.assert_const(out, E::zero())
}

/// Two-level binary MUX:
/// ```text
/// P = A + m0·(A + B)
/// Q = C + m0·C
/// Y = P + m1·(P + Q)
/// ```
///
/// Vars: Y=0, A=1, B=2, C=3, m0=4, m1=5.
pub fn addr_base_mux<C, E>(ctx: &mut C, vars: [C::Wire; 6]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let big_a = vars[1];
    let big_b = vars[2];
    let big_c = vars[3];
    let m0 = vars[4];
    let m1 = vars[5];

    let tmp1 = ctx.add(big_a, big_b); // mult 1
    let m0_ab = ctx.mul(m0, tmp1);
    let p = ctx.add(big_a, m0_ab);
    let m0_c = ctx.mul(m0, big_c); // mult 2
    let q = ctx.add(big_c, m0_c);
    let tmp2 = ctx.add(p, q); // mult 3
    let m1_pq = ctx.mul(m1, tmp2);
    let p_mux = ctx.add(p, m1_pq);
    let out = ctx.add(y, p_mux);
    ctx.assert_const(out, E::zero())
}

/// `Y + B + d·(A + B) = 0`. Vars: Y=0, A=1, B=2, d=3.
pub fn addr_index_mux<C, E>(ctx: &mut C, vars: [C::Wire; 4]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let a = vars[1];
    let b = vars[2];
    let d = vars[3];

    let tmp = ctx.add(a, b); // mult 1
    let d_ab = ctx.mul(d, tmp);
    let out = add_all(ctx, &[y, b, d_ab]);
    ctx.assert_const(out, E::zero())
}

/// 5-level binary tree MUX. Each node: `M = A + s·(A + B)`.
///
/// Vars: Y=0, s0=1, s1=2, s2=3, s3=4, s4=5, x0=6..x31=37.
pub fn mul_bit_extraction<C, E>(ctx: &mut C, vars: [C::Wire; 38]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let s: &[C::Wire] = &vars[1..=5];
    let x: &[C::Wire] = &vars[6..38];

    // 2-to-1 MUX: `a + sel·(a + b)`.
    fn mux<C: Context>(ctx: &mut C, sel: C::Wire, a: C::Wire, b: C::Wire) -> C::Wire {
        let diff = ctx.add(a, b);
        let term = ctx.mul(sel, diff);
        ctx.add(a, term)
    }

    // Level 0 (s0): 16 nodes.
    let m0: Vec<C::Wire> = (0..16)
        .map(|j| mux(ctx, s[0], x[2 * j], x[2 * j + 1]))
        .collect();

    // Level 1 (s1): 8 nodes.
    let m1: Vec<C::Wire> = (0..8)
        .map(|j| mux(ctx, s[1], m0[2 * j], m0[2 * j + 1]))
        .collect();

    // Level 2 (s2): 4 nodes.
    let m2: Vec<C::Wire> = (0..4)
        .map(|j| mux(ctx, s[2], m1[2 * j], m1[2 * j + 1]))
        .collect();

    // Level 3 (s3): 2 nodes.
    let m3: Vec<C::Wire> = (0..2)
        .map(|j| mux(ctx, s[3], m2[2 * j], m2[2 * j + 1]))
        .collect();

    // Level 4 (s4): 1 node → result.
    let result = mux(ctx, s[4], m3[0], m3[1]);

    let out = ctx.add(y, result);
    ctx.assert_const(out, E::zero())
}

/// `Y + 1 + M·(1 + m) = 0`. Vars: Y=0, M=1, m=2.
pub fn mul_force<C, E>(ctx: &mut C, vars: [C::Wire; 3]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let big_m = vars[1];
    let m = vars[2];

    let one = ctx.constant(E::one());
    let tmp = ctx.add(one, m); // mult 1
    let product = ctx.mul(big_m, tmp);
    let out = add_all(ctx, &[y, one, product]);
    ctx.assert_const(out, E::zero())
}

/// Don't-care (u0=1, u1=1) allows nesting:
/// ```text
/// R = u0·(W + A)
/// Y = A + R + u1·(S + A + R)
/// ```
///
/// Vars: Y=0, A=1, W=2, S=3, u0=4, u1=5.
pub fn acc_mux<C, E>(ctx: &mut C, vars: [C::Wire; 6]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let a = vars[1];
    let w = vars[2];
    let s = vars[3];
    let u0 = vars[4];
    let u1 = vars[5];

    let tmp = ctx.add(w, a); // mult 1
    let r = ctx.mul(u0, tmp);
    let sum = add_all(ctx, &[s, a, r]);
    let u1_term = ctx.mul(u1, sum); // mult 2
    let out = add_all(ctx, &[y, a, r, u1_term]);
    ctx.assert_const(out, E::zero())
}

/// ```text
/// P = PC + iota
/// D = S + P
/// E = R + P
/// Y = P + p0·D + p1·(k·D + p0·(D + k·D + E))
/// ```
///
/// Vars: Y=0, PC=1, iota=2, S=3, R=4, p0=5, p1=6, k=7.
pub fn pc_mux<C, E>(ctx: &mut C, vars: [C::Wire; 8]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let pc = vars[1];
    let iota = vars[2];
    let s = vars[3];
    let r = vars[4];
    let p0 = vars[5];
    let p1 = vars[6];
    let k = vars[7];

    let p = ctx.add(pc, iota);
    let d = ctx.add(s, p);
    let e_node = ctx.add(r, p);

    let kd = ctx.mul(k, d); // mult 1
    let p0_d = ctx.mul(p0, d); // mult 2
    let sum1 = add_all(ctx, &[d, kd, e_node]);
    let p0_inner = ctx.mul(p0, sum1); // mult 3
    let tmp = ctx.add(kd, p0_inner); // mult 4
    let p1_term = ctx.mul(p1, tmp);
    let out = add_all(ctx, &[y, p, p0_d, p1_term]);
    ctx.assert_const(out, E::zero())
}

/// Don't-care (r0=1, r1=1) allows nesting:
/// ```text
/// R = r0·D_inc
/// Y = SP + R + r1·(D_dec + R)
/// ```
///
/// Vars: Y=0, SP=1, D_inc=2, D_dec=3, r0=4, r1=5.
pub fn sp_mux<C, E>(ctx: &mut C, vars: [C::Wire; 6]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let sp = vars[1];
    let d_inc = vars[2];
    let d_dec = vars[3];
    let r0 = vars[4];
    let r1 = vars[5];

    let r = ctx.mul(r0, d_inc); // mult 1
    let tmp = ctx.add(d_dec, r); // mult 2
    let r1_term = ctx.mul(r1, tmp);
    let out = add_all(ctx, &[y, sp, r, r1_term]);
    ctx.assert_const(out, E::zero())
}

/// `Y + F + t·(N + F) = 0`. Vars: Y=0, F=1, N=2, t=3.
pub fn fp_mux<C, E>(ctx: &mut C, vars: [C::Wire; 4]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let y = vars[0];
    let f = vars[1];
    let n = vars[2];
    let t = vars[3];

    let tmp = ctx.add(n, f); // mult 1
    let t_nf = ctx.mul(t, tmp);
    let out = add_all(ctx, &[y, f, t_nf]);
    ctx.assert_const(out, E::zero())
}

// ===========================================================================
// END: CPU step circuit emulation
// ===========================================================================

// ===========================================================================
// BEGIN: Simple gates
// ===========================================================================

/// AND-gate-shaped constraint: `w0·w1 + w2 = 0`.
pub fn and_gate<C, E>(ctx: &mut C, vars: [C::Wire; 3]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let w0 = vars[0];
    let w1 = vars[1];
    let w2 = vars[2];
    let prod = ctx.mul(w0, w1);
    let out = ctx.add(prod, w2);
    ctx.assert_const(out, E::zero())
}

/// Linear constraint: `w0 + w1 = 0`.
pub fn linear_add<C, E>(ctx: &mut C, vars: [C::Wire; 2]) -> Result<(), C::Error>
where
    C: Context<Field = E>,
    E: Field,
{
    let a = vars[0];
    let b = vars[1];
    let out = ctx.add(a, b);
    ctx.assert_const(out, E::zero())
}

// ===========================================================================
// END: Simple gates
// ===========================================================================
