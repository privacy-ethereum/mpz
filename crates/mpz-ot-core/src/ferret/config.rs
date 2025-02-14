use std::{fmt::Debug, sync::Arc};

use derive_builder::Builder;

use mpz_core::lpn::{LpnParameters, LpnType};

use crate::ferret::cuckoo::HASH_NUM;

/// Computational security parameter.
pub(crate) const CSP: usize = 128;

#[cfg(test)]
pub(crate) const TEST_PARAMS: LpnParameters = LpnParameters {
    n: 9600,
    k: 1220,
    t: 600,
};

/// Ferret configuration.
#[derive(Clone, Builder)]
pub struct FerretConfig {
    /// LPN type.
    #[builder(default = "LpnType::Uniform")]
    lpn_type: LpnType,
    /// Whether to reserve bootstrap COTs.
    #[builder(default = "true")]
    reserve_bootstrap: bool,
    #[builder(setter(custom), default = "Arc::new(default_parameter_selector)")]
    param_selector: Arc<dyn Fn(LpnType, usize, usize) -> LpnParameters + Send + Sync + 'static>,
}

impl Debug for FerretConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FerretConfig")
            .field("lpn_type", &self.lpn_type)
            .field("reserve_bootstrap", &self.reserve_bootstrap)
            .finish_non_exhaustive()
    }
}

impl Default for FerretConfig {
    fn default() -> Self {
        Self {
            lpn_type: LpnType::Uniform,
            reserve_bootstrap: true,
            param_selector: Arc::new(default_parameter_selector),
        }
    }
}

impl FerretConfigBuilder {
    /// Configures the LPN parameter selector.
    ///
    /// The provided function must have the following signature:
    ///
    /// `(LpnType, available, additional) -> LpnParameters`
    ///
    /// where `available` is the current number of available COTs and
    /// `additional` is the number of COTs that still need to be generated.
    pub fn param_selector<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(LpnType, usize, usize) -> LpnParameters + Send + Sync + 'static,
    {
        self.param_selector = Some(Arc::new(f));
        self
    }
}

impl FerretConfig {
    /// Returns a new `FerretConfigBuilder`.
    pub fn builder() -> FerretConfigBuilder {
        FerretConfigBuilder::default()
    }

    /// Returns `true` if bootstrap COTs should be reserved.
    pub fn reserve_bootstrap(&self) -> bool {
        self.reserve_bootstrap
    }

    /// Returns the LPN type.
    pub fn lpn_type(&self) -> LpnType {
        self.lpn_type
    }

    /// Returns the cost of a bootstrap iteration.
    pub(crate) fn bootstrap_cost(&self) -> usize {
        match self.lpn_type {
            LpnType::Uniform => iteration_cost(self.lpn_type, UNIFORM_PARAMS[0]),
            LpnType::Regular => iteration_cost(self.lpn_type, REGULAR_PARAMS[0]),
        }
    }

    pub(crate) fn select_params(&self, available: usize, additional: usize) -> LpnParameters {
        (self.param_selector)(self.lpn_type, available, additional)
    }
}

fn default_parameter_selector(ty: LpnType, available: usize, additional: usize) -> LpnParameters {
    let params = match ty {
        LpnType::Uniform => UNIFORM_PARAMS,
        LpnType::Regular => REGULAR_PARAMS,
    };

    // *Assumes the parameters are in ascending order.*
    for param in params {
        let cost = iteration_cost(ty, *param);
        let net = param.t - cost;
        // If we don't have enough available we select the smallest parameters
        // immediately.
        if available <= cost || net >= additional {
            return *param;
        }
    }

    // If we reach here, we select the largest parameters.
    *params.last().unwrap()
}

/// Returns the number of COTs needed to execute an iteration with the given
/// parameters.
fn iteration_cost(ty: LpnType, params: LpnParameters) -> usize {
    match ty {
        // The number here is a rough estimation to ensure sufficient buffer.
        // It is hard to precisely compute the number because of the Cuckoo hashes.
        LpnType::Uniform => {
            let m = (1.5 * (params.t as f32)).ceil() as usize;
            m * ((2 * HASH_NUM as usize * params.n / m)
                .checked_next_power_of_two()
                .expect("The length should be less than usize::MAX / 2 - 1")
                .ilog2() as usize)
                + params.k
                + CSP
        }
        // In our chosen paramters, we always set n is divided by t and n/t is a power of 2.
        LpnType::Regular => {
            assert!(params.n % params.t == 0 && (params.n / params.t).is_power_of_two());
            params.t * ((params.n / params.t).ilog2() as usize) + params.k + CSP
        }
    }
}

static UNIFORM_PARAMS: &[LpnParameters] = &[
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

static REGULAR_PARAMS: &[LpnParameters] = &[
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
