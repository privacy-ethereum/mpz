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
#[derive(Debug)]
pub enum LpnType {
    /// Uniform error distribution.
    Uniform,
    /// Regular error distribution.
    Regular,
}

#[cfg(test)]
mod tests {
    use super::*;

    use msgs::LpnMatrixSeed;
    use receiver::Receiver;
    use sender::Sender;

    use crate::ideal::{cot::IdealCOT, mpcot::IdealMpcot};
    use crate::test::assert_cot;
    use crate::{MPCOTReceiverOutput, MPCOTSenderOutput, RCOTReceiverOutput, RCOTSenderOutput};
    use mpz_core::{lpn::LpnParameters, prg::Prg};

    const LPN_PARAMETERS_TEST: LpnParameters = LpnParameters {
        n: 9600,
        k: 1220,
        t: 600,
    };

    #[test]
    fn ferret_test() {
        let mut prg = Prg::new();
        let delta = prg.random_block();
        let mut ideal_cot = IdealCOT::default();
        let mut ideal_mpcot = IdealMpcot::default();

        ideal_cot.set_delta(delta);
        ideal_mpcot.set_delta(delta);

        let sender = Sender::new();
        let receiver = Receiver::new();

        // Invoke Ideal COT to init the Ferret setup phase.
        let (sender_cot, receiver_cot) = ideal_cot.random_correlated(LPN_PARAMETERS_TEST.k);

        let RCOTSenderOutput { msgs: v, .. } = sender_cot;
        let RCOTReceiverOutput {
            choices: u,
            msgs: w,
            ..
        } = receiver_cot;

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

        let (MPCOTSenderOutput { s, .. }, MPCOTReceiverOutput { r, .. }) =
            ideal_mpcot.extend(&query.0, query.1);

        let msgs = sender.extend(&s).unwrap();
        let (choices, received) = receiver.extend(&r).unwrap();

        assert_cot(delta, &choices, &msgs, &received);

        // extend twice
        let _ = sender.get_mpcot_query();
        let query = receiver.get_mpcot_query();

        let (MPCOTSenderOutput { s, .. }, MPCOTReceiverOutput { r, .. }) =
            ideal_mpcot.extend(&query.0, query.1);

        let msgs = sender.extend(&s).unwrap();
        let (choices, received) = receiver.extend(&r).unwrap();

        assert_cot(delta, &choices, &msgs, &received);
    }
}
