use derive_builder::Builder;

/// Generator configuration.
#[derive(Debug, Clone, Builder)]
pub struct GeneratorConfig {
    /// Whether to send commitments to output encodings.
    #[builder(default = "false", setter(custom))]
    pub(crate) encoding_commitments: bool,
}

impl GeneratorConfig {
    /// Creates a new builder for the generator configuration.
    pub fn builder() -> GeneratorConfigBuilder {
        GeneratorConfigBuilder::default()
    }
}

impl GeneratorConfigBuilder {
    /// Enable encoding commitments.
    pub fn encoding_commitments(&mut self) -> &mut Self {
        self.encoding_commitments = Some(true);
        self
    }
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        GeneratorConfigBuilder::default().build().unwrap()
    }
}
