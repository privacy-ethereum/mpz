use scoped_futures::ScopedBoxFuture;

use crate::Context;

pub(crate) async fn map<'a, F, T, R>(ctx: &'a mut Context, items: Vec<T>, f: F) -> Vec<R>
where
    F: for<'b> Fn(&'b mut Context, T) -> ScopedBoxFuture<'static, 'b, R>,
{
    let mut results = Vec::with_capacity(items.len());
    for item in items {
        results.push(f(ctx, item).await);
    }
    results
}

pub(crate) async fn join<'a, A, B, RA, RB>(ctx: &'a mut Context, a: A, b: B) -> (RA, RB)
where
    A: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, RA>,
    B: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, RB>,
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
    A: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, Result<RA, E>>,
    B: for<'b> FnOnce(&'b mut Context) -> ScopedBoxFuture<'a, 'b, Result<RB, E>>,
{
    let a = a(ctx).await?;
    let b = b(ctx).await?;
    Ok((a, b))
}
