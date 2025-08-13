use mpz_core::lpn::LpnParameters;

/// LPN parameters.
pub static LPN_PARAMS: &[LpnParameters] = &[
    LpnParameters {
        n: 545_656,
        k: 34_643,
        t: 1_050,
    },
    LpnParameters {
        n: 1_071_888,
        k: 40_800,
        t: 1720,
    },
    LpnParameters {
        n: 5_324_800,
        k: 240_000,
        t: 1_300,
    },
    LpnParameters {
        n: 10_488_928,
        k: 458_000,
        t: 1280,
    },
];
