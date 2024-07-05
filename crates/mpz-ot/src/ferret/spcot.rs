//! Implementation of the Single-Point COT (spcot) protocol in the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) paper.

use mpz_common::{cpu::CpuBackend, Context};
use mpz_core::Block;
use mpz_ot_core::{
    ferret::{
        spcot::{
            msgs::{ExtendFromSender, MaskBits},
            receiver::Receiver as ReceiverCore,
            sender::Sender as SenderCore,
        },
        CSP,
    },
    RCOTReceiverOutput, RCOTSenderOutput,
};
use serio::{stream::IoStreamExt as _, SinkExt as _};

use crate::{ferret::error::SPCOTError as Error, RandomCOTReceiver, RandomCOTSender};

/// SPCOT send.
///
/// # Arguments
///
/// * `ctx` - Thread context.
/// * `rcot` - Random COT sender.
/// * `delta` - Delta correlation.
/// * `hs` - The depth of the GGM trees.
pub(crate) async fn send<Ctx: Context, RandomCOT: RandomCOTSender<Ctx, Block>>(
    ctx: &mut Ctx,
    rcot: &mut RandomCOT,
    delta: Block,
    hs: &[usize],
) -> Result<Vec<Vec<Block>>, Error> {
    let mut sender = SenderCore::new().setup(delta);

    let h = hs.iter().sum();
    let RCOTSenderOutput { msgs: qss, .. } = rcot.send_random_correlated(ctx, h).await?;

    let masks: Vec<MaskBits> = ctx.io_mut().expect_next().await?;

    // extend
    let h_in = hs.to_vec();
    let (mut sender, extend_msg) = CpuBackend::blocking(move || {
        sender
            .extend(&h_in, &qss, &masks)
            .map(|extend_msg| (sender, extend_msg))
    })
    .await?;

    ctx.io_mut().send(extend_msg).await?;

    // batch check
    let RCOTSenderOutput { msgs: y_star, .. } = rcot.send_random_correlated(ctx, CSP).await?;

    let checkfr = ctx.io_mut().expect_next().await?;

    let (output, check_msg) = CpuBackend::blocking(move || {
        sender
            .check(&y_star, checkfr)
            .map(|(output, check_msg)| (output, check_msg))
    })
    .await?;

    ctx.io_mut().send(check_msg).await?;

    Ok(output)
}

/// SPCOT receive.
///
/// # Arguments
///
/// * `ctx` - Thread context.
/// * `rcot` - Random COT receiver.
/// * `alphas` - Vector of chosen positions.
/// * `hs` - The depth of the GGM trees.
pub(crate) async fn receive<Ctx: Context, RandomCOT: RandomCOTReceiver<Ctx, bool, Block>>(
    ctx: &mut Ctx,
    rcot: &mut RandomCOT,
    alphas: &[u32],
    hs: &[usize],
) -> Result<Vec<(Vec<Block>, u32)>, Error> {
    let mut receiver = ReceiverCore::new().setup();

    let h = hs.iter().sum();
    let RCOTReceiverOutput {
        choices: rss,
        msgs: tss,
        ..
    } = rcot.receive_random_correlated(ctx, h).await?;

    // extend
    let h_in = hs.to_vec();
    let alphas_in = alphas.to_vec();
    let (mut receiver, masks) = CpuBackend::blocking(move || {
        receiver
            .extend_mask_bits(&h_in, &alphas_in, &rss)
            .map(|mask| (receiver, mask))
    })
    .await?;

    ctx.io_mut().send(masks).await?;

    let extendfss: Vec<ExtendFromSender> = ctx.io_mut().expect_next().await?;

    let h_in = hs.to_vec();
    let alphas_in = alphas.to_vec();
    let mut receiver = CpuBackend::blocking(move || {
        receiver
            .extend(&h_in, &alphas_in, &tss, &extendfss)
            .map(|_| receiver)
    })
    .await?;

    // batch check
    let RCOTReceiverOutput {
        choices: x_star,
        msgs: z_star,
        ..
    } = rcot.receive_random_correlated(ctx, CSP).await?;

    let (mut receiver, checkfr) = CpuBackend::blocking(move || {
        receiver
            .check_pre(&x_star)
            .map(|checkfr| (receiver, checkfr))
    })
    .await?;

    ctx.io_mut().send(checkfr).await?;
    let check = ctx.io_mut().expect_next().await?;

    let output =
        CpuBackend::blocking(move || receiver.check(&z_star, check).map(|output| output)).await?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ideal::cot::ideal_rcot, Correlation};
    use mpz_common::executor::test_st_executor;

    #[tokio::test]
    async fn test_spcot() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);
        let (mut rcot_sender, mut rcot_receiver) = ideal_rcot();

        let hs = [8usize, 4];
        let alphas = [4u32, 2];
        let delta = rcot_sender.delta();

        let (mut output_sender, output_receiver) = tokio::try_join!(
            send(&mut ctx_sender, &mut rcot_sender, delta, &hs),
            receive(&mut ctx_receiver, &mut rcot_receiver, &alphas, &hs)
        )
        .unwrap();

        assert!(output_sender
            .iter_mut()
            .zip(output_receiver.iter())
            .all(|(vs, (ws, alpha))| {
                vs[*alpha as usize] ^= delta;
                vs == ws
            }));
    }
}
