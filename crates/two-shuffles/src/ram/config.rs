//! Protocol config.

use std::marker::PhantomData;

use mpz_fields::Field;
use rangeset::set::RangeSet;

use crate::strategy::FieldStrategy;

/// Protocol config.
pub struct Config<F, Strat>
where
    F: Field,
    Strat: FieldStrategy<F>,
{
    /// Addresses populated at setup.
    pub live_addrs: RangeSet<usize>,
    /// Bit-width of the value domain: each address stores one of
    /// `2^value_bits` distinct values.
    pub value_bits: usize,
    /// Total access budget.
    pub total_accesses: usize,
    /// Addresses whose post-teardown state is returned.
    pub export_addrs: RangeSet<usize>,
    _strat: PhantomData<(F, fn() -> Strat)>,
}

impl<F, Strat> Clone for Config<F, Strat>
where
    F: Field,
    Strat: FieldStrategy<F>,
{
    fn clone(&self) -> Self {
        Self {
            live_addrs: self.live_addrs.clone(),
            value_bits: self.value_bits,
            total_accesses: self.total_accesses,
            export_addrs: self.export_addrs.clone(),
            _strat: PhantomData,
        }
    }
}

impl<F, Strat> Config<F, Strat>
where
    F: Field,
    Strat: FieldStrategy<F>,
{
    /// Start building a [`Config`].
    pub fn builder(
        live_addrs: RangeSet<usize>,
        value_bits: usize,
        total_accesses: usize,
    ) -> ConfigBuilder<F, Strat> {
        ConfigBuilder::new(live_addrs, value_bits, total_accesses)
    }
}

/// Builder for [`Config`].
pub struct ConfigBuilder<F, Strat>
where
    F: Field,
    Strat: FieldStrategy<F>,
{
    live_addrs: RangeSet<usize>,
    value_bits: usize,
    total_accesses: usize,
    export_addrs: Option<RangeSet<usize>>,
    _strat: PhantomData<(F, fn() -> Strat)>,
}

impl<F, Strat> ConfigBuilder<F, Strat>
where
    F: Field,
    Strat: FieldStrategy<F>,
{
    /// New config builder.
    pub fn new(live_addrs: RangeSet<usize>, value_bits: usize, total_accesses: usize) -> Self {
        Self {
            live_addrs,
            value_bits,
            total_accesses,
            export_addrs: None,
            _strat: PhantomData,
        }
    }

    /// Override the default export set (which is all of `live_addrs`).
    /// The set must be a subset of `live_addrs`.
    pub fn export_addrs(mut self, set: RangeSet<usize>) -> Self {
        self.export_addrs = Some(set);
        self
    }

    /// Finalize the config.
    pub fn build(self) -> Result<Config<F, Strat>, Error> {
        if self.live_addrs.is_empty() {
            return Err(Error::EmptyLiveSet);
        }

        let export_addrs = self.export_addrs.unwrap_or_else(|| self.live_addrs.clone());
        if export_addrs.is_empty() {
            return Err(Error::EmptyExportSet);
        }
        // Can only export instantiated cells.
        if export_addrs
            .iter_values()
            .any(|a| !self.live_addrs.contains(&a))
        {
            return Err(Error::ExportNotSubset);
        }

        Ok(Config {
            live_addrs: self.live_addrs,
            value_bits: self.value_bits,
            total_accesses: self.total_accesses,
            export_addrs,
            _strat: PhantomData,
        })
    }
}

/// Errors raised by [`ConfigBuilder::build`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed an empty `live_addrs` set to
    /// [`Config::builder`].
    #[error("live_addrs must be non-empty")]
    EmptyLiveSet,

    /// Caller passed an empty `RangeSet` to
    /// [`ConfigBuilder::export_addrs`].
    #[error("export_addrs must be non-empty")]
    EmptyExportSet,

    /// `export_addrs` contains an address that is not in `live_addrs`.
    #[error("export_addrs must be a subset of live_addrs")]
    ExportNotSubset,
}
