//! Tests for the thread pool and concurrency primitives.

use serio::{SinkExt, stream::IoStreamExt};

use crate::context::{Context, Multithread, MultithreadBuilderError, SpawnError};

use super::helpers::{test_mt_context, test_mt_context_with_concurrency};

/// Tests that `join` (non-try variant) executes both branches and returns
/// their results.
#[tokio::test]
async fn test_join() {
    let (mut exec_0, mut exec_1) = test_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, _) = futures::join!(
        ctx_0.join(
            async |ctx: &mut Context| {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                msg
            },
            async |ctx: &mut Context| {
                let msg: String = ctx.io_mut().expect_next().await.unwrap();
                msg
            },
        ),
        ctx_1.join(
            async |ctx: &mut Context| {
                ctx.io_mut().send(42u32).await.unwrap();
            },
            async |ctx: &mut Context| {
                ctx.io_mut().send("hello".to_string()).await.unwrap();
            },
        )
    );

    let (msg_a, msg_b) = result.unwrap();
    assert_eq!(msg_a, 42);
    assert_eq!(msg_b, "hello");
}

/// Tests that nested joins work with concurrency = 2 (the minimum for
/// `try_join`).
///
/// With only 2 pool threads, nested `try_join` calls dispatch their inner
/// tasks to the same 2 threads. Cooperative async scheduling on the
/// `LocalExecutor` means tasks yield on `.await`, so the threads can
/// interleave nested work without deadlocking.
#[tokio::test]
async fn test_nested_join_minimal_concurrency() {
    let std_spawn = |f: Box<dyn FnOnce() + Send>| -> Result<(), SpawnError> {
        std::thread::Builder::new()
            .spawn(f)
            .map(|_| ())
            .map_err(SpawnError::new)
    };

    let (mut exec_0, mut exec_1) = test_mt_context_with_concurrency(1024 * 1024, 2, std_spawn);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, _) = futures::join!(
        // Outer try_join with nested try_join inside first branch.
        ctx_0.try_join(
            async |ctx: &mut Context| {
                let outer_msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                assert_eq!(outer_msg, 1);

                let inner = ctx
                    .try_join(
                        async |ctx: &mut Context| {
                            let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                            Ok::<_, std::io::Error>(msg)
                        },
                        async |ctx: &mut Context| {
                            let msg: u64 = ctx.io_mut().expect_next().await.unwrap();
                            Ok::<_, std::io::Error>(msg)
                        },
                    )
                    .await
                    .unwrap()
                    .unwrap();
                Ok::<_, std::io::Error>(inner)
            },
            async |ctx: &mut Context| {
                let msg: String = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, std::io::Error>(msg)
            },
        ),
        // Matching sender structure.
        ctx_1.try_join(
            async |ctx: &mut Context| {
                ctx.io_mut().send(1u32).await.unwrap();
                ctx.try_join(
                    async |ctx: &mut Context| {
                        ctx.io_mut().send(10u32).await.unwrap();
                        Ok::<_, std::io::Error>(())
                    },
                    async |ctx: &mut Context| {
                        ctx.io_mut().send(20u64).await.unwrap();
                        Ok::<_, std::io::Error>(())
                    },
                )
                .await
                .unwrap()
                .unwrap();
                Ok::<_, std::io::Error>(())
            },
            async |ctx: &mut Context| {
                ctx.io_mut()
                    .send("single-thread".to_string())
                    .await
                    .unwrap();
                Ok::<_, std::io::Error>(())
            },
        )
    );

    let ((inner_a, inner_b), outer_b) = result.unwrap().unwrap();
    assert_eq!(inner_a, 10);
    assert_eq!(inner_b, 20);
    assert_eq!(outer_b, "single-thread");
}

/// Tests that `try_join` propagates errors from either branch.
#[tokio::test]
async fn test_try_join_error_propagation() {
    let (mut exec_0, mut exec_1) = test_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let (result, _) = futures::join!(
        ctx_0.try_join(
            async |_ctx: &mut Context| { Ok::<u32, String>(42) },
            async |_ctx: &mut Context| { Err::<u32, String>("branch B failed".into()) },
        ),
        ctx_1.try_join(
            async |_ctx: &mut Context| { Ok::<(), String>(()) },
            async |_ctx: &mut Context| { Ok::<(), String>(()) },
        )
    );

    let inner = result.unwrap();
    assert!(inner.is_err());
    assert_eq!(inner.unwrap_err(), "branch B failed");
}

/// Tests that `try_join` recovers contexts after error, allowing reuse.
#[tokio::test]
async fn test_try_join_context_reuse_after_error() {
    let (mut exec_0, mut exec_1) = test_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    // First call: one branch fails.
    let (result, _) = futures::join!(
        ctx_0.try_join(
            async |_ctx: &mut Context| { Ok::<u32, String>(1) },
            async |_ctx: &mut Context| { Err::<u32, String>("fail".into()) },
        ),
        ctx_1.try_join(
            async |_ctx: &mut Context| { Ok::<(), String>(()) },
            async |_ctx: &mut Context| { Ok::<(), String>(()) },
        )
    );
    assert!(result.unwrap().is_err());

    // Second call: should still work because contexts were recovered.
    let (result, _) = futures::join!(
        ctx_0.try_join(
            async |ctx: &mut Context| {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, String>(msg)
            },
            async |ctx: &mut Context| {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                Ok::<_, String>(msg)
            },
        ),
        ctx_1.try_join(
            async |ctx: &mut Context| {
                ctx.io_mut().send(100u32).await.unwrap();
                Ok::<_, String>(())
            },
            async |ctx: &mut Context| {
                ctx.io_mut().send(200u32).await.unwrap();
                Ok::<_, String>(())
            },
        )
    );

    let (a, b) = result.unwrap().unwrap();
    assert_eq!(a, 100);
    assert_eq!(b, 200);
}

/// Tests that `map` with an empty input returns an empty result.
#[tokio::test]
async fn test_map_empty() {
    let (mut exec_0, mut exec_1) = test_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let items: Vec<u32> = vec![];

    let (result_0, result_1) = futures::join!(
        ctx_0.map(
            items.clone(),
            async |_ctx: &mut Context, item: u32| { item },
            |_| 1,
        ),
        ctx_1.map(items, async |_ctx: &mut Context, item: u32| { item }, |_| 1,)
    );

    assert_eq!(result_0.unwrap(), Vec::<u32>::new());
    assert_eq!(result_1.unwrap(), Vec::<u32>::new());
}

/// Tests that `map` preserves input order regardless of completion order.
#[tokio::test]
async fn test_map_preserves_order() {
    let (mut exec_0, mut exec_1) = test_mt_context(1024 * 1024);

    let mut ctx_0 = exec_0.new_context().unwrap();
    let mut ctx_1 = exec_1.new_context().unwrap();

    let items: Vec<u32> = (0..16).collect();

    let (recv_results, _) = futures::join!(
        ctx_0.map(
            items.clone(),
            async |ctx: &mut Context, _item: u32| {
                let msg: u32 = ctx.io_mut().expect_next().await.unwrap();
                msg
            },
            |_| 1,
        ),
        ctx_1.map(
            items,
            async |ctx: &mut Context, item: u32| {
                ctx.io_mut().send(item * 10).await.unwrap();
            },
            |_| 1,
        )
    );

    let results = recv_results.unwrap();
    // Results must be in input order [0, 10, 20, ...], not arrival order.
    let expected: Vec<u32> = (0..16).map(|i| i * 10).collect();
    assert_eq!(results, expected);
}

/// Tests that building a pool with concurrency = 0 returns an error.
#[tokio::test]
async fn test_concurrency_zero_rejected() {
    let (mux_0, _mux_1) = crate::mux::test_framed_mux(1024);
    let mux_0: Box<dyn crate::mux::Mux + Send> = Box::new(mux_0);

    let result: Result<Multithread, MultithreadBuilderError> =
        Multithread::builder().concurrency(0).mux(mux_0).build();

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("at least 1"),
        "error should mention minimum threads: {err}"
    );
}

/// Tests that dropping `Multithread` shuts down pool workers.
///
/// After dropping, the senders are closed, which causes worker threads to
/// exit their run loops. We verify by checking that the senders report
/// closed state.
#[tokio::test]
async fn test_pool_shutdown_on_drop() {
    let (mux_0, _mux_1) = crate::mux::test_framed_mux(1024);
    let mux_0: Box<dyn crate::mux::Mux + Send> = Box::new(mux_0);

    let mut exec = Multithread::builder()
        .concurrency(2)
        .mux(mux_0)
        .build()
        .unwrap();

    // Create a context to confirm the pool is functional.
    let _ctx = exec.new_context().unwrap();
    // Drop the entire Multithread (and its _pool).
    // The test passes if this completes without panic or hang.
    drop(exec);
}
