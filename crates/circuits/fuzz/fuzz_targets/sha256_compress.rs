#![no_main]

use itybity::{FromBitIterator, ToBits};
use libfuzzer_sys::fuzz_target;
use mpz_circuits::{
    WitnessCtx,
    sha256::{AND_PER_BLOCK, compress},
};
use mpz_fields::gf2::Gf2;

fuzz_target!(|data: &[u8]| {
    // Need 64 bytes block + 32 bytes state = 96 bytes.
    if data.len() < 96 {
        return;
    }
    let block: [u8; 64] = data[..64].try_into().unwrap();
    let state: [u32; 8] = core::array::from_fn(|i| {
        u32::from_be_bytes(data[64 + i * 4..64 + (i + 1) * 4].try_into().unwrap())
    });

    // The gadget byte-swaps the message internally, so feed the little-endian
    // (memory-order) read of the block bytes.
    let msg_words: [u32; 16] =
        core::array::from_fn(|i| u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()));
    let msg: [Gf2; 512] = <[Gf2; 512]>::from_lsb0_iter(msg_words.iter_lsb0());
    let state_in: [Gf2; 256] = <[Gf2; 256]>::from_lsb0_iter(state.iter_lsb0());

    let mut witness = Vec::with_capacity(AND_PER_BLOCK);
    let mut ctx = WitnessCtx {
        witness: &mut witness,
    };
    let out = compress(&mut ctx, msg, state_in);
    let got: [u32; 8] = <[u32; 8]>::from_lsb0_iter(out.iter().map(|g| g.0));

    let mut expected = state;
    sha2::compress256(&mut expected, &[block.into()]);

    assert_eq!(got, expected);
});
