use mpz_circuits_new::WitnessCtx;
use mpz_fields::gf2::Gf2;

pub(crate) fn to_bits<const N: usize>(v: u64) -> [Gf2; N] {
    let mut out = [Gf2(false); N];
    for i in 0..N {
        out[i] = Gf2((v >> i) & 1 != 0);
    }
    out
}

pub(crate) fn from_bits<const N: usize>(b: [Gf2; N]) -> u64 {
    let mut v = 0u64;
    for i in 0..N {
        if b[i].0 {
            v |= 1u64 << i;
        }
    }
    v
}

pub(crate) fn run_bin<F, const N: usize>(g: F, a: u64, b: u64) -> u64
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; N], [Gf2; N]) -> [Gf2; N],
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    from_bits(g(&mut ctx, to_bits(a), to_bits(b)))
}

pub(crate) fn run_un<F, const N: usize>(g: F, a: u64) -> u64
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; N]) -> [Gf2; N],
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    from_bits(g(&mut ctx, to_bits(a)))
}

pub(crate) fn run_bin_bit<F, const N: usize>(g: F, a: u64, b: u64) -> bool
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; N], [Gf2; N]) -> Gf2,
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    g(&mut ctx, to_bits(a), to_bits(b)).0
}

pub(crate) fn run_un_bit<F, const N: usize>(g: F, a: u64) -> bool
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; N]) -> Gf2,
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    g(&mut ctx, to_bits(a)).0
}

pub(crate) fn run_conv<F, const N: usize, const M: usize>(g: F, a: u64) -> u64
where
    F: for<'a, 'b> FnOnce(&'a mut WitnessCtx<'b, Gf2>, [Gf2; N]) -> [Gf2; M],
{
    let mut w = Vec::new();
    let mut ctx = WitnessCtx { witness: &mut w };
    from_bits(g(&mut ctx, to_bits(a)))
}

pub(crate) fn prng() -> impl Iterator<Item = u64> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    std::iter::from_fn(move || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        Some(state)
    })
}


pub(crate) fn pairs_u64(n: usize) -> Vec<(u64, u64)> {
    let mut p = prng();
    (0..n)
        .map(|_| (p.next().unwrap(), p.next().unwrap()))
        .collect()
}
