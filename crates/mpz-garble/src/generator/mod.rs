//! An implementation of a garbled circuit generator.

mod config;
mod error;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_common::{scoped, Context};
use mpz_core::hash::Hash;
use mpz_garble_core::{
    encoding_state, ChaChaEncoder, EncodedValue, Encoder, EncodingCommitment,
    Generator as GeneratorCore, GeneratorOutput,
};
use serio::SinkExt;
use tracing::{span, Level};

use crate::{
    memory::EncodingMemory,
    ot::OTSendEncoding,
    value::{CircuitRefs, ValueId, ValueRef},
    AssignedValues,
};

pub use config::{GeneratorConfig, GeneratorConfigBuilder};
pub use error::GeneratorError;

/// A garbled circuit generator.
#[derive(Debug, Default)]
pub struct Generator {
    config: GeneratorConfig,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// The encoder used to encode values
    encoder: ChaChaEncoder,
    /// Encodings of values
    memory: EncodingMemory<encoding_state::Full>,
    /// Transferred garbled circuits
    ///
    /// Each circuit is uniquely identified by its (input, output) references. Optionally, the garbled circuit may have been hashed.
    garbled: HashMap<CircuitRefs, Option<Hash>>,
    /// The set of values that are currently active.
    ///
    /// A value is considered active when it has been encoded and sent to the evaluator.
    ///
    /// This is used to guarantee that the same encoding is never used
    /// with different active values.
    active: HashSet<ValueId>,
}

impl Generator {
    /// Create a new generator.
    pub fn new(config: GeneratorConfig, encoder_seed: [u8; 32]) -> Self {
        Self {
            config,
            state: Mutex::new(State::new(ChaChaEncoder::new(encoder_seed))),
        }
    }

    /// Convenience method for grabbing a lock to the state.
    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Returns the seed used to generate encodings.
    pub(crate) fn seed(&self) -> Vec<u8> {
        self.state().encoder.seed()
    }

    /// Returns the encoding for a value.
    pub fn get_encoding(&self, value: &ValueRef) -> Option<EncodedValue<encoding_state::Full>> {
        self.state().memory.get_encoding(value)
    }

    /// Returns the encodings for a slice of values.
    pub fn get_encodings(
        &self,
        values: &[ValueRef],
    ) -> Result<Vec<EncodedValue<encoding_state::Full>>, GeneratorError> {
        let state = self.state();
        values
            .iter()
            .map(|value| {
                state
                    .memory
                    .get_encoding(value)
                    .ok_or_else(|| GeneratorError::MissingEncoding(value.clone()))
            })
            .collect()
    }

    pub(crate) fn get_encodings_by_id(
        &self,
        ids: &[ValueId],
    ) -> Option<Vec<EncodedValue<encoding_state::Full>>> {
        let state = self.state();

        ids.iter()
            .map(|id| state.memory.get_encoding_by_id(id))
            .collect::<Option<Vec<_>>>()
    }

    /// Generates encoding for the provided input value.
    ///
    /// If an encoding for a value have already been generated, it is ignored.
    ///
    /// # Panics
    ///
    /// If the provided value type does not match the value reference.
    pub fn generate_input_encoding(&self, value: &ValueRef, typ: &ValueType) {
        self.state().encode(value, typ);
    }

    /// Generates encodings for the provided input values.
    ///
    /// If encodings for a value have already been generated, it is ignored.
    ///
    /// # Panics
    ///
    /// If the provided value type is an array
    pub(crate) fn generate_input_encodings_by_id(&self, values: &[(ValueId, ValueType)]) {
        let mut state = self.state();
        for (value_id, value_typ) in values {
            state.encode_by_id(value_id, value_typ);
        }
    }

    /// Transfer active encodings for the provided assigned values.
    ///
    /// # Arguments
    ///
    /// - `id` - The ID of this operation
    /// - `values` - The assigned values
    /// - `sink` - The sink to send the encodings to the evaluator
    /// - `ot` - The OT sender
    pub async fn setup_assigned_values<Ctx: Context, OT: OTSendEncoding<Ctx> + Send>(
        &self,
        ctx: &mut Ctx,
        values: &AssignedValues,
        ot: &mut OT,
    ) -> Result<(), GeneratorError> {
        let ot_send_values = values.blind.clone();
        let mut direct_send_values = values.public.clone();
        direct_send_values.extend(values.private.iter().cloned());

        ctx.try_join(
            scoped!(|ctx| async move {
                self.direct_send_active_encodings(ctx, &direct_send_values)
                    .await
            }),
            scoped!(|ctx| async move {
                self.ot_send_active_encodings(ctx, &ot_send_values, ot)
                    .await
            }),
        )
        .await??;

        Ok(())
    }

    /// Sends the encodings of the provided value to the evaluator via oblivious transfer.
    ///
    /// # Arguments
    ///
    /// - `id` - The ID of this operation
    /// - `values` - The values to send
    /// - `ot` - The OT sender
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub(crate) async fn ot_send_active_encodings<Ctx: Context, OT: OTSendEncoding<Ctx>>(
        &self,
        ctx: &mut Ctx,
        values: &[(ValueId, ValueType)],
        ot: &mut OT,
    ) -> Result<(), GeneratorError> {
        if values.is_empty() {
            return Ok(());
        }

        let full_encodings = {
            let mut state = self.state();
            // Filter out any values that are already active
            let mut values = values
                .iter()
                .filter(|(id, _)| !state.active.contains(id))
                .collect::<Vec<_>>();
            values.sort_by(|(id_a, _), (id_b, _)| id_a.cmp(id_b));

            values
                .iter()
                .map(|(id, _)| state.activate_encoding(id))
                .collect::<Result<Vec<_>, GeneratorError>>()?
        };

        ot.send(ctx, full_encodings).await?;

        Ok(())
    }

    /// Directly sends the active encodings of the provided values to the evaluator.
    ///
    /// # Arguments
    ///
    /// - `values` - The values to send
    /// - `sink` - The sink to send the encodings to the evaluator
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub(crate) async fn direct_send_active_encodings<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        values: &[(ValueId, Value)],
    ) -> Result<(), GeneratorError> {
        if values.is_empty() {
            return Ok(());
        }

        let active_encodings = {
            let mut state = self.state();
            // Filter out any values that are already active
            let mut values = values
                .iter()
                .filter(|(id, _)| !state.active.contains(id))
                .collect::<Vec<_>>();
            values.sort_by(|(id_a, _), (id_b, _)| id_a.cmp(id_b));

            values
                .iter()
                .map(|(id, value)| {
                    let full_encoding = state.activate_encoding(id)?;
                    Ok(full_encoding.select(value.clone())?)
                })
                .collect::<Result<Vec<_>, GeneratorError>>()?
        };

        ctx.io_mut().send(active_encodings).await?;

        Ok(())
    }

    /// Generate a garbled circuit, streaming the encrypted gates to the evaluator in batches.
    ///
    /// Returns the encodings of the outputs, and optionally a hash of the circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to garble
    /// * `inputs` - The inputs of the circuit
    /// * `outputs` - The outputs of the circuit
    /// * `sink` - The sink to send the garbled circuit to the evaluator
    /// * `hash` - Whether to hash the circuit
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub async fn generate<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        hash: bool,
    ) -> Result<(Vec<EncodedValue<encoding_state::Full>>, Option<Hash>), GeneratorError> {
        let refs = CircuitRefs {
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
        };

        let (delta, inputs) = {
            let state = self.state();

            // If the circuit has already been garbled, return early
            if let Some(hash) = state.garbled.get(&refs) {
                return Ok((
                    outputs
                        .iter()
                        .map(|output| {
                            state
                                .memory
                                .get_encoding(output)
                                .expect("encoding exists if circuit is garbled already")
                        })
                        .collect(),
                    *hash,
                ));
            }

            let delta = state.encoder.delta();
            let inputs = inputs
                .iter()
                .map(|value| {
                    state
                        .memory
                        .get_encoding(value)
                        .ok_or(GeneratorError::MissingEncoding(value.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?;

            (delta, inputs)
        };

        // Garble the circuit in batches, streaming the encrypted gates from the worker thread.
        let span = span!(Level::TRACE, "worker");
        let GeneratorOutput {
            outputs: encoded_outputs,
            hash,
        } = ctx
            .blocking(scoped!(move |ctx| async move {
                let _enter = span.enter();
                let mut gen = GeneratorCore::default();
                let mut gen_iter = gen.generate_batched(&circ, delta, inputs)?;
                let io = ctx.io_mut();

                if hash {
                    gen_iter.enable_hasher();
                }

                while let Some(batch) = gen_iter.by_ref().next() {
                    io.feed(batch).await?;
                }

                gen_iter.finish().map_err(GeneratorError::from)
            }))
            .await??;

        if self.config.encoding_commitments {
            let commitments: Vec<EncodingCommitment> = encoded_outputs
                .iter()
                .map(|output| output.commit())
                .collect();
            ctx.io_mut().feed(commitments).await?;
        }

        ctx.io_mut().flush().await?;

        // Add the outputs to the memory and set as active.
        let mut state = self.state();
        for (output, encoding) in outputs.iter().zip(encoded_outputs.iter()) {
            state.memory.set_encoding(output, encoding.clone())?;
            output.iter().for_each(|id| {
                state.active.insert(id.clone());
            });
        }

        state.garbled.insert(refs, hash);

        Ok((encoded_outputs, hash))
    }

    /// Send value decoding information to the evaluator.
    ///
    /// # Arguments
    ///
    /// * `values` - The values to decode
    /// * `sink` - The sink to send the decodings with
    pub async fn decode<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
    ) -> Result<(), GeneratorError> {
        let decodings = {
            let state = self.state();
            values
                .iter()
                .map(|value| {
                    state
                        .memory
                        .get_encoding(value)
                        .ok_or(GeneratorError::MissingEncoding(value.clone()))
                        .map(|encoding| encoding.decoding())
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        ctx.io_mut().send(decodings).await?;

        Ok(())
    }
}

impl State {
    fn new(encoder: ChaChaEncoder) -> Self {
        Self {
            encoder,
            ..Default::default()
        }
    }

    /// Generates an encoding for a value
    ///
    /// If an encoding for the value already exists, it is returned instead.
    fn encode(&mut self, value: &ValueRef, ty: &ValueType) -> EncodedValue<encoding_state::Full> {
        match (value, ty) {
            (ValueRef::Value { id }, ty) if !ty.is_array() => self.encode_by_id(id, ty),
            (ValueRef::Array(array), ValueType::Array(elem_ty, len)) if array.len() == *len => {
                let encodings = array
                    .ids()
                    .iter()
                    .map(|id| self.encode_by_id(id, elem_ty))
                    .collect();

                EncodedValue::Array(encodings)
            }
            _ => panic!("invalid value and type combination: {:?} {:?}", value, ty),
        }
    }

    /// Generates an encoding for a value
    ///
    /// If an encoding for the value already exists, it is returned instead.
    fn encode_by_id(&mut self, id: &ValueId, ty: &ValueType) -> EncodedValue<encoding_state::Full> {
        if let Some(encoding) = self.memory.get_encoding_by_id(id) {
            encoding
        } else {
            let encoding = self.encoder.encode_by_type(id.to_u64(), ty);
            self.memory
                .set_encoding_by_id(id, encoding.clone())
                .expect("encoding does not already exist");
            encoding
        }
    }

    fn activate_encoding(
        &mut self,
        id: &ValueId,
    ) -> Result<EncodedValue<encoding_state::Full>, GeneratorError> {
        let encoding = self
            .memory
            .get_encoding_by_id(id)
            .ok_or_else(|| GeneratorError::MissingEncoding(ValueRef::Value { id: id.clone() }))?;

        // Returns error if the encoding is already active
        if !self.active.insert(id.clone()) {
            return Err(GeneratorError::DuplicateEncoding(ValueRef::Value {
                id: id.clone(),
            }));
        }

        Ok(encoding)
    }
}
