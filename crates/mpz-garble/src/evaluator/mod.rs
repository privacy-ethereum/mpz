//! An implementation of a garbled circuit evaluator.

mod config;
mod error;

use std::{
    collections::{HashMap, HashSet},
    mem,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use mpz_circuits::{
    types::{TypeError, Value, ValueType},
    Circuit,
};
use mpz_common::{cpu::CpuBackend, executor::DummyExecutor, scoped, Context};
use mpz_core::hash::Hash;
use mpz_garble_core::{
    encoding_state, Decoding, EncodedValue, EncodingCommitment, EncryptedGateBatch,
    Evaluator as EvaluatorCore, EvaluatorOutput, GarbledCircuit,
};
use mpz_ot::TransferId;
use serio::stream::IoStreamExt;
use utils::iter::FilterDrain;

use crate::{
    memory::EncodingMemory,
    ot::{EncodingReceiverOutput, OTReceiveEncoding, OTVerifyEncoding},
    value::{CircuitRefs, ValueId, ValueRef},
    AssignedValues, Generator, GeneratorConfigBuilder,
};

pub use config::{EvaluatorConfig, EvaluatorConfigBuilder};
pub use error::EvaluatorError;

use error::VerificationError;

/// A garbled circuit evaluator.
#[derive(Debug)]
pub struct Evaluator {
    config: EvaluatorConfig,
    state: Mutex<State>,
}

impl Default for Evaluator {
    fn default() -> Self {
        Self {
            config: EvaluatorConfigBuilder::default().build().unwrap(),
            state: Mutex::new(State::default()),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    /// Encodings of values
    memory: EncodingMemory<encoding_state::Active>,
    /// Encoded values which were received either directly or via OT
    received_values: HashMap<ValueId, ValueType>,
    /// Values which have been decoded
    decoded_values: HashSet<ValueId>,
    /// Pre-transferred garbled circuits
    ///
    /// A map used to look up a garbled circuit by its unique (inputs, outputs) reference.
    garbled_circuits: HashMap<CircuitRefs, GarbledCircuit>,
    /// OT logs
    ot_log: HashMap<TransferId, Vec<ValueId>>,
    /// Garbled circuit logs
    circuit_logs: Vec<EvaluatorLog>,
    /// Decodings of values received from the generator
    decoding_logs: HashMap<ValueRef, Decoding>,
}

impl Evaluator {
    /// Creates a new evaluator.
    pub fn new(config: EvaluatorConfig) -> Self {
        Self {
            config,
            ..Default::default()
        }
    }

    /// Convenience method for grabbing a lock to the state.
    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Sets a value as decoded.
    ///
    /// # Errors
    ///
    /// Returns an error if the value has already been decoded.
    pub(crate) fn set_decoded(&self, value: &ValueRef) -> Result<(), EvaluatorError> {
        let mut state = self.state();
        // Check that none of the values in this reference have already been decoded.
        // We track every individual value of an array separately to ensure that a decoding
        // is never overwritten.
        for id in value.iter() {
            if !state.decoded_values.insert(id.clone()) {
                return Err(EvaluatorError::DuplicateDecoding(id.clone()));
            }
        }

        Ok(())
    }

    /// Returns the encoding for a value.
    pub fn get_encoding(&self, value: &ValueRef) -> Option<EncodedValue<encoding_state::Active>> {
        self.state().memory.get_encoding(value)
    }

    /// Returns the encodings for a slice of values.
    pub fn get_encodings(
        &self,
        values: &[ValueRef],
    ) -> Result<Vec<EncodedValue<encoding_state::Active>>, EvaluatorError> {
        let state = self.state();

        values
            .iter()
            .map(|value| {
                state
                    .memory
                    .get_encoding(value)
                    .ok_or_else(|| EvaluatorError::MissingEncoding(value.clone()))
            })
            .collect()
    }

    /// Adds a decoding log entry.
    pub(crate) fn add_decoding_log(&self, value: &ValueRef, decoding: Decoding) {
        self.state().decoding_logs.insert(value.clone(), decoding);
    }

    /// Transfer encodings for the provided assigned values.
    ///
    /// # Arguments
    ///
    /// - `id` - The id of this operation
    /// - `values` - The assigned values
    /// - `stream` - The stream to receive the encodings from the generator
    /// - `ot` - The OT receiver
    pub async fn setup_assigned_values<Ctx: Context, OT: OTReceiveEncoding<Ctx> + Send>(
        &self,
        ctx: &mut Ctx,
        values: &AssignedValues,
        ot: &mut OT,
    ) -> Result<(), EvaluatorError> {
        // Filter out any values that are already active.
        let (mut ot_recv_values, mut direct_recv_values) = {
            let state = self.state();
            let ot_recv_values = values
                .private
                .iter()
                .filter(|(id, _)| !state.memory.contains(id))
                .cloned()
                .collect::<Vec<_>>();
            let direct_recv_values = values
                .public
                .iter()
                .map(|(id, value)| (id.clone(), value.value_type()))
                .chain(values.blind.clone())
                .filter(|(id, _)| !state.memory.contains(id))
                .collect::<Vec<_>>();

            (ot_recv_values, direct_recv_values)
        };

        ot_recv_values.sort_by(|(id1, _), (id2, _)| id1.cmp(id2));
        direct_recv_values.sort_by(|(id1, _), (id2, _)| id1.cmp(id2));

        ctx.try_join(
            scoped!(|ctx| async move {
                self.direct_receive_active_encodings(ctx, &direct_recv_values)
                    .await
            }),
            scoped!(|ctx| async move {
                self.ot_receive_active_encodings(ctx, &ot_recv_values, ot)
                    .await
            }),
        )
        .await??;

        Ok(())
    }

    /// Receives active encodings for the provided values via oblivious transfer.
    ///
    /// # Arguments
    /// - `id` - The id of this operation
    /// - `values` - The values to receive via oblivious transfer.
    /// - `ot` - The oblivious transfer receiver
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub async fn ot_receive_active_encodings<Ctx: Context, OT: OTReceiveEncoding<Ctx>>(
        &self,
        ctx: &mut Ctx,
        values: &[(ValueId, Value)],
        ot: &mut OT,
    ) -> Result<(), EvaluatorError> {
        if values.is_empty() {
            return Ok(());
        }

        let (ot_recv_ids, ot_recv_values): (Vec<ValueId>, Vec<Value>) =
            values.iter().cloned().unzip();

        let EncodingReceiverOutput {
            id,
            encodings: active_encodings,
        } = ot.receive(ctx, ot_recv_values).await?;

        // Make sure the generator sent the expected number of values.
        // This should be handled by the ot receiver, but we double-check anyways :)
        if active_encodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: active_encodings.len(),
            });
        }

        let mut state = self.state();

        // Add the OT log
        state.ot_log.insert(id, ot_recv_ids);

        for ((id, value), active_encoding) in values.iter().zip(active_encodings) {
            let expected_ty = value.value_type();
            // Make sure the generator sent the expected type.
            // This is also handled by the ot receiver, but we're paranoid.
            if active_encoding.value_type() != expected_ty {
                return Err(TypeError::UnexpectedType {
                    expected: expected_ty,
                    actual: active_encoding.value_type(),
                })?;
            }
            // Add the received values to the memory.
            state.memory.set_encoding_by_id(id, active_encoding)?;
            state.received_values.insert(id.clone(), expected_ty);
        }

        Ok(())
    }

    /// Receives active encodings for the provided values directly from the generator.
    ///
    /// # Arguments
    /// - `values` - The values and types expected to be received
    /// - `stream` - The stream of messages from the generator
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub async fn direct_receive_active_encodings<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        values: &[(ValueId, ValueType)],
    ) -> Result<(), EvaluatorError> {
        if values.is_empty() {
            return Ok(());
        }

        let active_encodings: Vec<EncodedValue<encoding_state::Active>> =
            ctx.io_mut().expect_next().await?;

        // Make sure the generator sent the expected number of values.
        if active_encodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: active_encodings.len(),
            });
        }

        let mut state = self.state();
        for ((id, expected_ty), active_encoding) in values.iter().zip(active_encodings) {
            // Make sure the generator sent the expected type.
            if &active_encoding.value_type() != expected_ty {
                return Err(TypeError::UnexpectedType {
                    expected: expected_ty.clone(),
                    actual: active_encoding.value_type(),
                })?;
            }
            // Add the received values to the memory.
            state.memory.set_encoding_by_id(id, active_encoding)?;
            state
                .received_values
                .insert(id.clone(), expected_ty.clone());
        }

        Ok(())
    }

    /// Receives a garbled circuit from the generator, storing it for later evaluation.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to receive
    /// * `inputs` - The inputs to the circuit
    /// * `outputs` - The outputs from the circuit
    /// * `stream` - The stream from the generator
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
    pub async fn receive_garbled_circuit<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), EvaluatorError> {
        let refs = CircuitRefs {
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
        };

        if self.state().garbled_circuits.contains_key(&refs) {
            return Err(EvaluatorError::DuplicateCircuit);
        }

        let gate_count = circ.and_count();
        let mut gates = Vec::with_capacity(gate_count);

        while gates.len() < gate_count {
            let batch: EncryptedGateBatch = ctx.io_mut().expect_next().await?;
            gates.extend_from_slice(&batch.into_array());
        }

        // Trim off any batch padding.
        gates.truncate(gate_count);

        // If configured, expect the output encoding commitments
        let encoding_commitments = if self.config.encoding_commitments {
            let commitments: Vec<EncodingCommitment> = ctx.io_mut().expect_next().await?;

            // Make sure the generator sent the expected number of commitments.
            if commitments.len() != circ.outputs().len() {
                return Err(EvaluatorError::IncorrectValueCount {
                    expected: circ.outputs().len(),
                    actual: commitments.len(),
                });
            }

            Some(commitments)
        } else {
            None
        };

        self.state().garbled_circuits.insert(
            refs,
            GarbledCircuit {
                gates,
                commitments: encoding_commitments,
            },
        );

        Ok(())
    }

    /// Evaluate a circuit.
    ///
    /// Returns the encoded outputs of the evaluated circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to evaluate
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs from the circuit.
    /// * `stream` - The stream of encrypted gates
    #[tracing::instrument(fields(thread = %ctx.id()), skip_all, err)]
    pub async fn evaluate<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<Vec<EncodedValue<encoding_state::Active>>, EvaluatorError> {
        let refs = CircuitRefs {
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
        };

        let encoded_inputs = {
            let state = self.state();
            inputs
                .iter()
                .map(|value_ref| {
                    state
                        .memory
                        .get_encoding(value_ref)
                        .ok_or_else(|| EvaluatorError::MissingEncoding(value_ref.clone()))
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let existing_garbled_circuit = self.state().garbled_circuits.remove(&refs);

        // If we've already received the garbled circuit, we evaluate it, otherwise we stream the encrypted gates
        // from the generator.
        let EvaluatorOutput {
            outputs: encoded_outputs,
            hash,
        } = if let Some(GarbledCircuit { gates, commitments }) = existing_garbled_circuit {
            let circ = circ.clone();
            let hash = self.config.log_circuits;
            let output = CpuBackend::blocking(move || {
                let mut ev = EvaluatorCore::default();
                let mut ev_consumer = ev.evaluate(&circ, encoded_inputs)?;

                if hash {
                    ev_consumer.enable_hasher();
                }

                for gate in gates {
                    ev_consumer.next(gate);
                }

                ev_consumer.finish().map_err(EvaluatorError::from)
            })
            .await?;

            if self.config.encoding_commitments {
                for (output, commitment) in output
                    .outputs
                    .iter()
                    .zip(commitments.expect("commitments were checked to be present"))
                {
                    commitment.verify(output)?;
                }
            }

            output
        } else {
            let circ = circ.clone();
            let hash = self.config.log_circuits;
            let output = ctx
                .blocking(scoped!(move |ctx| async move {
                    let mut ev = EvaluatorCore::default();
                    let mut ev_consumer = ev.evaluate_batched(&circ, encoded_inputs)?;
                    let io = ctx.io_mut();

                    if hash {
                        ev_consumer.enable_hasher();
                    }

                    while ev_consumer.wants_gates() {
                        let batch: EncryptedGateBatch = io.expect_next().await?;
                        ev_consumer.next(batch);
                    }

                    ev_consumer.finish().map_err(EvaluatorError::from)
                }))
                .await??;

            if self.config.encoding_commitments {
                let commitments: Vec<EncodingCommitment> = ctx.io_mut().expect_next().await?;

                // Make sure the generator sent the expected number of commitments.
                if commitments.len() != output.outputs.len() {
                    return Err(EvaluatorError::IncorrectValueCount {
                        expected: output.outputs.len(),
                        actual: commitments.len(),
                    });
                }

                for (output, commitment) in output.outputs.iter().zip(commitments) {
                    commitment.verify(output)?;
                }
            }

            output
        };

        // Add the output encodings to the memory.
        let mut state = self.state();
        for (output, encoding) in outputs.iter().zip(encoded_outputs.iter()) {
            state.memory.set_encoding(output, encoding.clone())?;
        }

        // If configured, log the circuit evaluation
        if self.config.log_circuits {
            let hash = hash.unwrap();
            state.circuit_logs.push(EvaluatorLog::new(
                inputs.to_vec(),
                outputs.to_vec(),
                circ,
                hash,
            ));
        }

        Ok(encoded_outputs)
    }

    /// Receive decoding information for a set of values from the generator
    /// and decode them.
    ///
    /// # Arguments
    ///
    /// * `values` - The values to decode
    /// * `stream` - The stream from the generator
    pub async fn decode<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
    ) -> Result<Vec<Value>, EvaluatorError> {
        let decodings: Vec<Decoding> = ctx.io_mut().expect_next().await?;

        // Make sure the generator sent the expected number of decodings.
        if decodings.len() != values.len() {
            return Err(EvaluatorError::IncorrectValueCount {
                expected: values.len(),
                actual: decodings.len(),
            });
        }

        for (value, decoding) in values.iter().zip(decodings.iter()) {
            self.set_decoded(value)?;
            if self.config.log_decodings {
                self.add_decoding_log(value, decoding.clone());
            }
        }

        let active_encodings = values
            .iter()
            .map(|value| {
                self.get_encoding(value)
                    .ok_or_else(|| EvaluatorError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let decoded_values = decodings
            .iter()
            .zip(active_encodings.iter())
            .map(|(decoding, encoding)| encoding.decode(decoding))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(decoded_values)
    }

    /// Verifies all the evaluator state using the generator's encoder seed and the OT verifier.
    ///
    /// # Arguments
    ///
    /// * `encoder_seed` - The seed used by the generator to generate encodings for input values.
    /// * `ot` - The OT verifier.
    pub async fn verify<Ctx: Context, T: OTVerifyEncoding<Ctx>>(
        &mut self,
        ctx: &mut Ctx,
        encoder_seed: [u8; 32],
        ot: &mut T,
    ) -> Result<(), EvaluatorError> {
        // This function requires an exclusive reference to self, and because this
        // object owns the Mutex, we are guaranteed that no other thread is accessing
        // the state during verification.

        let gen = Generator::new(
            GeneratorConfigBuilder::default().build().unwrap(),
            encoder_seed,
        );

        // Generate encodings for all received values
        let received_values: Vec<(ValueId, ValueType)> =
            self.state().received_values.drain().collect();
        gen.generate_input_encodings_by_id(&received_values);

        let (ot_log, mut circuit_logs) = {
            let mut state = self.state();
            (
                mem::take(&mut state.ot_log),
                mem::take(&mut state.circuit_logs),
            )
        };

        // Verify all OTs in the log
        for (ot_id, value_ids) in ot_log {
            let encoded_values = gen
                .get_encodings_by_id(&value_ids)
                .expect("encodings should be present");
            ot.verify(ctx, ot_id, encoded_values).await?
        }

        // Verify all garbled circuits in the log
        let mut dummy_ctx = DummyExecutor::default();
        while !circuit_logs.is_empty() {
            // drain_filter is not stabilized.. such is life.
            // here we drain out log batches for which we have all the input encodings
            // computed at this point.
            let log_batch = circuit_logs
                .filter_drain(|log| {
                    log.inputs
                        .iter()
                        .all(|input| gen.get_encoding(input).is_some())
                })
                .collect::<Vec<_>>();

            for log in log_batch {
                // Compute the garbled circuit digest
                let (_, digest) = gen
                    .generate(
                        &mut dummy_ctx,
                        log.circ.clone(),
                        &log.inputs,
                        &log.outputs,
                        true,
                    )
                    .await
                    .map_err(VerificationError::from)?;

                if digest.unwrap() != log.hash {
                    return Err(VerificationError::InvalidGarbledCircuit.into());
                }
            }
        }

        // Verify all decodings in the log
        for (value, decoding) in self.state().decoding_logs.drain() {
            let encoding = gen.get_encoding(&value).expect("encoding should exist");

            if encoding.decoding() != decoding {
                return Err(VerificationError::InvalidDecoding)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct EvaluatorLog {
    inputs: Vec<ValueRef>,
    outputs: Vec<ValueRef>,
    circ: Arc<Circuit>,
    hash: Hash,
}

impl EvaluatorLog {
    pub(crate) fn new(
        inputs: Vec<ValueRef>,
        outputs: Vec<ValueRef>,
        circ: Arc<Circuit>,
        digest: Hash,
    ) -> Self {
        Self {
            inputs,
            outputs,
            circ,
            hash: digest,
        }
    }
}
