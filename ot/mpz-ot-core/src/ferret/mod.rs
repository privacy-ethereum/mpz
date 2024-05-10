//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.

use mpz_core::lpn::LpnParameters;

pub mod cuckoo;
pub mod error;
pub mod mpcot;
pub mod msgs;
pub mod receiver;
pub mod sender;
pub mod spcot;

/// Computational security parameter
pub const CSP: usize = 128;

/// Number of hashes in Cuckoo hash.
pub const CUCKOO_HASH_NUM: usize = 3;

/// Trial numbers in Cuckoo hash insertion.
pub const CUCKOO_TRIAL_NUM: usize = 100;

/// LPN parameters with regular noise.
/// Derived from https://github.com/emp-toolkit/emp-ot/blob/master/emp-ot/ferret/constants.h
pub const LPN_PARAMETERS_REGULAR: LpnParameters = LpnParameters {
    n: 10180608,
    k: 124000,
    t: 4971,
};

/// LPN parameters with uniform noise.
/// Derived from Table 2.
pub const LPN_PARAMETERS_UNIFORM: LpnParameters = LpnParameters {
    n: 10616092,
    k: 588160,
    t: 1324,
};

/// The type of Lpn parameters.
pub enum LpnType {
    /// Uniform error distribution.
    Uniform,
    /// Regular error distribution.
    Regular,
}

#[cfg(test)]
mod tests {
    use super::{
        msgs::LpnMatrixSeed, receiver::Receiver as FerretReceiver, sender::Sender as FerretSender,
        LpnType,
    };
    use crate::ideal::{
        ideal_cot::{CotMsgForReceiver, CotMsgForSender, IdealCOT},
        ideal_mpcot::{IdealMpcot, MpcotMsgForReceiver, MpcotMsgForSender},
    };
    use mpz_core::{lpn::LpnParameters, prg::Prg};
    use rand::SeedableRng;

    const LPN_PARAMETERS_TEST: LpnParameters = LpnParameters {
        n: 9600,
        k: 1220,
        t: 600,
    };

    #[test]
    fn ferret_test() {
        let mut prg = Prg::from_seed([1u8; 16].into());
        let delta = prg.random_block();
        let mut ideal_cot = IdealCOT::new_with_delta(delta);
        let mut ideal_mpcot = IdealMpcot::init_with_delta(delta);

        let sender = FerretSender::new();
        let receiver = FerretReceiver::new();

        // Invoke Ideal COT to init the Ferret setup phase.
        let (sender_cot, receiver_cot) = ideal_cot.extend(LPN_PARAMETERS_TEST.k);

        let CotMsgForSender { qs: v } = sender_cot;
        let CotMsgForReceiver { rs: u, ts: w } = receiver_cot;

        // receiver generates the random seed of lpn matrix.
        let lpn_matrix_seed = prg.random_block();

        // init the setup of sender and receiver.
        let (mut receiver, seed) = receiver
            .setup(
                LPN_PARAMETERS_TEST,
                LpnType::Regular,
                lpn_matrix_seed,
                &u,
                &w,
            )
            .unwrap();

        let LpnMatrixSeed {
            seed: lpn_matrix_seed,
        } = seed;

        let mut sender = sender
            .setup(
                delta,
                LPN_PARAMETERS_TEST,
                LpnType::Regular,
                lpn_matrix_seed,
                &v,
            )
            .unwrap();

        // extend once
        let _ = sender.get_mpcot_query();
        let query = receiver.get_mpcot_query();

        let (sender_mpcot, receiver_mpcot) = ideal_mpcot.extend(&query.0, query.1, query.2);

        let MpcotMsgForSender { s } = sender_mpcot;
        let MpcotMsgForReceiver { r } = receiver_mpcot;

        let sender_out = sender.extend(&s).unwrap();
        let receiver_out = receiver.extend(&r).unwrap();

        assert!(ideal_cot.check(
            CotMsgForSender { qs: sender_out },
            CotMsgForReceiver {
                rs: receiver_out.0,
                ts: receiver_out.1,
            },
        ));

        // extend twice
        let _ = sender.get_mpcot_query();
        let query = receiver.get_mpcot_query();

        let (sender_mpcot, receiver_mpcot) = ideal_mpcot.extend(&query.0, query.1, query.2);

        let MpcotMsgForSender { s } = sender_mpcot;
        let MpcotMsgForReceiver { r } = receiver_mpcot;

        let sender_out = sender.extend(&s).unwrap();
        let receiver_out = receiver.extend(&r).unwrap();

        assert!(ideal_cot.check(
            CotMsgForSender { qs: sender_out },
            CotMsgForReceiver {
                rs: receiver_out.0,
                ts: receiver_out.1,
            },
        ));
    }
}
