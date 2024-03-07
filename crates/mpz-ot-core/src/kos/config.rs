use derive_builder::Builder;

/// KOS15 sender configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct SenderConfig {
    /// Enables committed sender functionality.
    #[builder(setter(custom), default = "false")]
    sender_commit: bool,
}

impl SenderConfigBuilder {
    /// Enables committed sender functionality.
    pub fn sender_commit(&mut self) -> &mut Self {
        self.sender_commit = Some(true);
        self
    }
}

impl SenderConfig {
    /// Creates a new builder for SenderConfig.
    pub fn builder() -> SenderConfigBuilder {
        SenderConfigBuilder::default()
    }

    /// Enables committed sender functionality.
    pub fn sender_commit(&self) -> bool {
        self.sender_commit
    }
}

/// KOS15 receiver configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct ReceiverConfig {
    /// Enables committed sender functionality.
    #[builder(setter(custom), default = "false")]
    sender_commit: bool,
}

impl ReceiverConfigBuilder {
    /// Enables committed sender functionality.
    pub fn sender_commit(&mut self) -> &mut Self {
        self.sender_commit = Some(true);
        self
    }
}

impl ReceiverConfig {
    /// Creates a new builder for ReceiverConfig.
    pub fn builder() -> ReceiverConfigBuilder {
        ReceiverConfigBuilder::default()
    }

    /// Enables committed sender functionality.
    pub fn sender_commit(&self) -> bool {
        self.sender_commit
    }
}
