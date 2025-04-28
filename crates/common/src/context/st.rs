use crate::Context;

pub(crate) async fn map<'a, F, T, R>(ctx: &'a mut Context, items: Vec<T>, f: F) -> Vec<R>
where
    F: for<'b> AsyncFn(&'b mut Context, T) -> R,
{
    let mut results = Vec::with_capacity(items.len());
    for item in items {
        results.push(f(ctx, item).await);
    }
    results
}

pub(crate) async fn join<'a, A, B, RA, RB>(ctx: &'a mut Context, a: A, b: B) -> (RA, RB)
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> RA,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> RB,
{
    let a = a(ctx).await;
    let b = b(ctx).await;
    (a, b)
}

pub(crate) async fn try_join<'a, A, B, RA, RB, E>(
    ctx: &'a mut Context,
    a: A,
    b: B,
) -> Result<(RA, RB), E>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E>,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E>,
{
    let a = a(ctx).await?;
    let b = b(ctx).await?;
    Ok((a, b))
}

pub(crate) async fn try_join3<'a, A, B, C, RA, RB, RC, E>(
    ctx: &'a mut Context,
    a: A,
    b: B,
    c: C,
) -> Result<(RA, RB, RC), E>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E>,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E>,
    C: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RC, E>,
{
    let a = a(ctx).await?;
    let b = b(ctx).await?;
    let c = c(ctx).await?;
    Ok((a, b, c))
}

pub(crate) async fn try_join4<'a, A, B, C, D, RA, RB, RC, RD, E>(
    ctx: &'a mut Context,
    a: A,
    b: B,
    c: C,
    d: D,
) -> Result<(RA, RB, RC, RD), E>
where
    A: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RA, E>,
    B: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RB, E>,
    C: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RC, E>,
    D: for<'b> AsyncFnOnce(&'b mut Context) -> Result<RD, E>,
{
    let a = a(ctx).await?;
    let b = b(ctx).await?;
    let c = c(ctx).await?;
    let d = d(ctx).await?;
    Ok((a, b, c, d))
}
