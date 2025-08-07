use derive_builder::Builder;

const DEFAULT_BATCH_SIZE: usize = 4096;

/// KOS15 sender configuration.
#[derive(Debug, Clone, Builder)]
pub struct SenderConfig {
    /// Batch size for each flush.
    #[builder(default = "DEFAULT_BATCH_SIZE")]
    batch_size: usize,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl SenderConfig {
    /// Creates a new builder for SenderConfig.
    pub fn builder() -> SenderConfigBuilder {
        SenderConfigBuilder::default()
    }

    /// Returns the batch size for each flush.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}

/// KOS15 receiver configuration.
#[derive(Debug, Clone, Builder)]
pub struct ReceiverConfig {
    /// Batch size for each flush.
    #[builder(default = "DEFAULT_BATCH_SIZE")]
    batch_size: usize,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

impl ReceiverConfig {
    /// Creates a new builder for ReceiverConfig.
    pub fn builder() -> ReceiverConfigBuilder {
        ReceiverConfigBuilder::default()
    }

    /// Returns the batch size for each flush.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }
}
