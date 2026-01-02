use derive_builder::Builder;

/// An empirically chosen default value which provides the best performance.
const DEFAULT_BATCH_SIZE: usize = 200_000;

/// Prover configuration.
#[derive(Debug, Clone, Builder)]
pub struct ProverConfig {
    /// Target number of AND gates per consistency-check batch.
    ///
    /// The actual size of a batch may exceed this value slightly because
    /// individual calls are never split across batches. If the last call in
    /// a batch would exceed the target size, the entire call is included in
    /// that batch.
    #[builder(default = "DEFAULT_BATCH_SIZE")]
    batch_size: usize,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl ProverConfig {
    /// Creates a new builder for ProverConfig.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns target number of AND gates per consistency-check batch.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

/// Verifier configuration.
#[derive(Debug, Clone, Builder)]
pub struct VerifierConfig {
    /// Target number of AND gates per consistency-check batch.
    ///
    /// The actual size of a batch may exceed this value slightly because
    /// individual calls are never split across batches. If the last call in
    /// a batch would exceed the target size, the entire call is included in
    /// that batch.
    #[builder(default = "DEFAULT_BATCH_SIZE")]
    batch_size: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl VerifierConfig {
    /// Creates a new builder for VerifierConfig.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns target number of AND gates per consistency-check batch.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}
