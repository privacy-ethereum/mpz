use derive_builder::Builder;

/// CO15 sender configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct SenderConfig {
    /// Whether the Receiver should commit to their choices.
    #[builder(setter(custom), default = "false")]
    receiver_commit: bool,
}

impl SenderConfigBuilder {
    /// Sets the Receiver to commit to their choices.
    pub fn receiver_commit(&mut self) -> &mut Self {
        self.receiver_commit = Some(true);
        self
    }
}

impl SenderConfig {
    /// Creates a new builder for SenderConfig.
    pub fn builder() -> SenderConfigBuilder {
        SenderConfigBuilder::default()
    }

    /// Whether the Receiver should commit to their choices.
    pub fn receiver_commit(&self) -> bool {
        self.receiver_commit
    }
}

/// CO15 receiver configuration.
#[derive(Debug, Default, Clone, Builder)]
pub struct ReceiverConfig {
    /// Whether the Receiver should commit to their choices.
    #[builder(setter(custom), default = "false")]
    receiver_commit: bool,
}

impl ReceiverConfigBuilder {
    /// Sets the Receiver to commit to their choices.
    pub fn receiver_commit(&mut self) -> &mut Self {
        self.receiver_commit = Some(true);
        self
    }
}

impl ReceiverConfig {
    /// Creates a new builder for ReceiverConfig.
    pub fn builder() -> ReceiverConfigBuilder {
        ReceiverConfigBuilder::default()
    }

    /// Whether the Receiver should commit to their choices.
    pub fn receiver_commit(&self) -> bool {
        self.receiver_commit
    }
}
