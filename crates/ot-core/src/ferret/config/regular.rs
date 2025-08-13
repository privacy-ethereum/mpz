use mpz_core::lpn::LpnParameters;

/// LPN parameters.
pub static LPN_PARAMS: &[LpnParameters] = &[
    LpnParameters {
        n: 518_656,
        k: 34_643,
        t: 1_013,
    },
    LpnParameters {
        n: 1_740_800,
        k: 66_400,
        t: 1700,
    },
    LpnParameters {
        n: 5_324_800,
        k: 240_000,
        t: 1_300,
    },
    LpnParameters {
        n: 10_485_760,
        k: 458_000,
        t: 1280,
    },
];
