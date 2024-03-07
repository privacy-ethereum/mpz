//! An implementation of a garbled circuit generator.

mod config;
mod error;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{Sink, SinkExt};
use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_core::hash::Hash;
use mpz_garble_core::{
    encoding_state, msg::GarbleMessage, ChaChaEncoder, EncodedValue, Encoder,
    Generator as GeneratorCore,
};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

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
    pub async fn setup_assigned_values<
        S: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        OT: OTSendEncoding,
    >(
        &self,
        id: &str,
        values: &AssignedValues,
        sink: &mut S,
        ot: &OT,
    ) -> Result<(), GeneratorError> {
        let ot_send_values = values.blind.clone();
        let mut direct_send_values = values.public.clone();
        direct_send_values.extend(values.private.iter().cloned());

        futures::try_join!(
            self.ot_send_active_encodings(id, &ot_send_values, ot),
            self.direct_send_active_encodings(&direct_send_values, sink)
        )?;

        Ok(())
    }

    /// Sends the encodings of the provided value to the evaluator via oblivious transfer.
    ///
    /// # Arguments
    ///
    /// - `id` - The ID of this operation
    /// - `values` - The values to send
    /// - `ot` - The OT sender
    pub(crate) async fn ot_send_active_encodings<OT: OTSendEncoding>(
        &self,
        id: &str,
        values: &[(ValueId, ValueType)],
        ot: &OT,
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

        ot.send(id, full_encodings).await?;

        Ok(())
    }

    /// Directly sends the active encodings of the provided values to the evaluator.
    ///
    /// # Arguments
    ///
    /// - `values` - The values to send
    /// - `sink` - The sink to send the encodings to the evaluator
    pub(crate) async fn direct_send_active_encodings<
        S: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
    >(
        &self,
        values: &[(ValueId, Value)],
        sink: &mut S,
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

        sink.send(GarbleMessage::ActiveValues(active_encodings))
            .await?;

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
    pub async fn generate<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut S,
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

        let mut gen = if hash {
            GeneratorCore::new_with_hasher(circ.clone(), delta, &inputs)?
        } else {
            GeneratorCore::new(circ.clone(), delta, &inputs)?
        };

        let mut batch: Vec<_>;
        let batch_size = self.config.batch_size;
        while !gen.is_complete() {
            // Move the generator to another thread to produce the next batch
            // then send it back
            (gen, batch) = Backend::spawn(move || {
                let batch = gen.by_ref().take(batch_size).collect();
                (gen, batch)
            })
            .await;

            if !batch.is_empty() {
                sink.send(GarbleMessage::EncryptedGates(batch)).await?;
            }
        }

        let encoded_outputs = gen.outputs()?;
        let hash = gen.hash();

        if self.config.encoding_commitments {
            let commitments = encoded_outputs
                .iter()
                .map(|output| output.commit())
                .collect();

            sink.send(GarbleMessage::EncodingCommitments(commitments))
                .await?;
        }

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
    pub async fn decode<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &self,
        values: &[ValueRef],
        sink: &mut S,
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

        sink.send(GarbleMessage::ValueDecodings(decodings)).await?;

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
