//! Implementation of the Multiple-Point COT (mpcot) protocol in the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) paper.

use mpz_common::{cpu::CpuBackend, Context};
use mpz_core::{prg::Prg, Block};
use mpz_ot_core::ferret::{
    mpcot::{
        msgs::HashSeed, receiver::Receiver as UniformReceiverCore,
        receiver_regular::Receiver as RegularReceiverCore, sender::Sender as UniformSender,
        sender_regular::Sender as RegularSender,
    },
    LpnType,
};
use serio::{stream::IoStreamExt as _, SinkExt as _};

use crate::{
    ferret::{error::MPCOTError as Error, spcot},
    RandomCOTReceiver, RandomCOTSender,
};

/// MPCOT send.
///
/// # Arguments.
///
/// * `ctx` - Thread context.
/// * `rcot` - Random COT sender.
/// * `delta` - Delta correlation.
/// * `lpn_type` - The type of LPN.
/// * `t` - The number of queried indices.
/// * `n` - The total number of indices.
pub(crate) async fn send<Ctx: Context, RandomCOT: RandomCOTSender<Ctx, Block>>(
    ctx: &mut Ctx,
    rcot: &mut RandomCOT,
    delta: Block,
    lpn_type: LpnType,
    t: u32,
    n: u32,
) -> Result<Vec<Block>, Error> {
    match lpn_type {
        LpnType::Uniform => {
            let hash_seed: HashSeed = ctx.io_mut().expect_next().await?;

            let (sender, hs) = CpuBackend::blocking(move || {
                UniformSender::new()
                    .setup(delta, hash_seed)
                    .pre_extend(t, n)
            })
            .await?;

            let st = spcot::send(ctx, rcot, delta, &hs).await?;

            let (_, output) = CpuBackend::blocking(move || sender.extend(&st)).await?;

            Ok(output)
        }
        LpnType::Regular => {
            let (sender, hs) =
                CpuBackend::blocking(move || RegularSender::new().setup(delta).pre_extend(t, n))
                    .await?;

            let st = spcot::send(ctx, rcot, delta, &hs).await?;

            let (_, output) = CpuBackend::blocking(move || sender.extend(&st)).await?;

            Ok(output)
        }
    }
}

/// MPCOT receive.
///
/// # Arguments
///
/// * `ctx` - Thread context.
/// * `rcot` - Random COT receiver.
/// * `lpn_type` - The type of LPN.
/// * `alphas` - The queried indices.
/// * `n` - The total number of indices.
pub(crate) async fn receive<Ctx: Context, RandomCOT: RandomCOTReceiver<Ctx, bool, Block>>(
    ctx: &mut Ctx,
    rcot: &mut RandomCOT,
    lpn_type: LpnType,
    alphas: Vec<u32>,
    n: u32,
) -> Result<Vec<Block>, Error> {
    match lpn_type {
        LpnType::Uniform => {
            let hash_seed = Prg::new().random_block();

            let (receiver, hash_seed) = UniformReceiverCore::new().setup(hash_seed);

            ctx.io_mut().send(hash_seed).await?;

            let (receiver, h_and_pos) =
                CpuBackend::blocking(move || receiver.pre_extend(&alphas, n)).await?;

            let mut hs = vec![0usize; h_and_pos.len()];

            let mut pos = vec![0u32; h_and_pos.len()];
            for (index, (h, p)) in h_and_pos.iter().enumerate() {
                hs[index] = *h;
                pos[index] = *p;
            }

            let rt = spcot::receive(ctx, rcot, &pos, &hs).await?;
            let rt: Vec<Vec<Block>> = rt.into_iter().map(|(elem, _)| elem).collect();
            let (_, output) = CpuBackend::blocking(move || receiver.extend(&rt)).await?;

            Ok(output)
        }
        LpnType::Regular => {
            let receiver = RegularReceiverCore::new().setup();

            let (receiver, h_and_pos) =
                CpuBackend::blocking(move || receiver.pre_extend(&alphas, n)).await?;

            let mut hs = vec![0usize; h_and_pos.len()];

            let mut pos = vec![0u32; h_and_pos.len()];
            for (index, (h, p)) in h_and_pos.iter().enumerate() {
                hs[index] = *h;
                pos[index] = *p;
            }

            let rt = spcot::receive(ctx, rcot, &pos, &hs).await?;
            let rt: Vec<Vec<Block>> = rt.into_iter().map(|(elem, _)| elem).collect();
            let (_, output) = CpuBackend::blocking(move || receiver.extend(&rt)).await?;

            Ok(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ideal::cot::ideal_rcot;
    use mpz_common::executor::test_st_executor;
    use mpz_ot_core::ferret::LpnType;
    use rstest::*;

    #[rstest]
    #[case(LpnType::Uniform)]
    #[case(LpnType::Regular)]
    #[tokio::test]
    async fn test_mpcot(#[case] lpn_type: LpnType) {
        use crate::Correlation;

        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);
        let (mut rcot_sender, mut rcot_receiver) = ideal_rcot();

        let alphas = match lpn_type {
            LpnType::Uniform => vec![0, 1, 3, 4, 2],
            LpnType::Regular => vec![0, 3, 4, 7, 9],
        };

        let t = alphas.len();
        let n = 10;
        let delta = rcot_sender.delta();

        let (mut output_sender, output_receiver) = tokio::try_join!(
            send(
                &mut ctx_sender,
                &mut rcot_sender,
                delta,
                lpn_type,
                t as u32,
                n
            ),
            receive(
                &mut ctx_receiver,
                &mut rcot_receiver,
                lpn_type,
                alphas.clone(),
                n
            )
        )
        .unwrap();

        for i in alphas {
            output_sender[i as usize] ^= delta;
        }

        assert_eq!(output_sender, output_receiver);
    }
}
