//! Configuration for the [`Prover`](crate::Prover) and
//! [`Verifier`](crate::Verifier).

use crate::DEFAULT_CHUNK_CAP;

/// Configuration shared by a [`Prover`](crate::Prover) and a
/// [`Verifier`](crate::Verifier).
///
/// `chunk_cap` and `segment_cost` shape proving and MUST match on both sides
/// for the parties to agree. `id` is a purely local logging label — it is
/// attached to the party's tracing spans so concurrent instances can be told
/// apart, and need not match (or be set on) the peer.
///
/// Build one with [`Config::builder`], or use [`Config::default`] for the
/// standard settings.
#[derive(Debug, Clone)]
pub struct Config {
    id: Option<u64>,
    chunk_cap: Option<usize>,
    segment_cost: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: None,
            chunk_cap: Some(DEFAULT_CHUNK_CAP),
            segment_cost: None,
        }
    }
}

impl Config {
    /// Returns a [`ConfigBuilder`] initialized to the defaults.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }

    /// The instance identifier attached to this party's tracing spans, if set.
    ///
    /// A logging label only: it lets one prover/verifier instance's spans be
    /// distinguished from another's when several run concurrently in a process.
    /// It does not affect the protocol.
    pub fn id(&self) -> Option<u64> {
        self.id
    }

    /// The maximum number of operations executed per chunk. See
    /// [`ConfigBuilder::chunk_cap`].
    pub fn chunk_cap(&self) -> Option<usize> {
        self.chunk_cap
    }

    /// The gate-cost target per proving segment. See
    /// [`ConfigBuilder::segment_cost`].
    pub fn segment_cost(&self) -> Option<usize> {
        self.segment_cost
    }
}

/// Builder for a [`Config`].
///
/// Created by [`Config::builder`]; starts from [`Config::default`] and overrides
/// only the fields that are set.
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            config: Config::default(),
        }
    }
}

impl ConfigBuilder {
    /// Sets the instance identifier attached to this party's tracing spans.
    ///
    /// Purely a logging label to disambiguate concurrent instances; it has no
    /// effect on the protocol and need not match the peer's.
    pub fn id(mut self, id: u64) -> Self {
        self.config.id = Some(id);
        self
    }

    /// Sets the maximum number of operations executed per chunk.
    ///
    /// `Some(cap)` bounds each chunk to at most `cap` operations, trading proof
    /// granularity against memory use; `None` places no bound and lets a chunk
    /// run until the program completes or traps. Defaults to
    /// [`Some(DEFAULT_CHUNK_CAP)`](crate::DEFAULT_CHUNK_CAP). Must match the
    /// peer's setting for the two sides to agree.
    pub fn chunk_cap(mut self, cap: Option<usize>) -> Self {
        self.config.chunk_cap = cap;
        self
    }

    /// Sets the gate-cost target per proving segment.
    ///
    /// `Some(cost)` splits each chunk's trace into segments of roughly `cost`
    /// gate bits, committed and folded by parallel workers; `None` (the default)
    /// auto-derives the target from the chunk cap so a full chunk splits into
    /// about [`TARGET_SEGMENTS`](crate::TARGET_SEGMENTS) segments. Must match the
    /// peer's setting for the two sides to agree.
    pub fn segment_cost(mut self, cost: Option<usize>) -> Self {
        self.config.segment_cost = cost;
        self
    }

    /// Consumes the builder, returning the configured [`Config`].
    pub fn build(self) -> Config {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_carries_standard_settings() {
        let config = Config::default();
        assert_eq!(config.id(), None);
        assert_eq!(config.chunk_cap(), Some(DEFAULT_CHUNK_CAP));
        assert_eq!(config.segment_cost(), None);
    }

    #[test]
    fn builder_overrides_only_set_fields() {
        let config = Config::builder().id(7).segment_cost(Some(5_000)).build();
        assert_eq!(config.id(), Some(7));
        // Untouched: still the default.
        assert_eq!(config.chunk_cap(), Some(DEFAULT_CHUNK_CAP));
        assert_eq!(config.segment_cost(), Some(5_000));
    }
}
