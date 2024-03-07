//! An implementation of the Dual-execution with Asymmetric Privacy (DEAP) protocol.
//!
//! For more information, see the [DEAP specification](https://docs.tlsnotary.org/mpc/deap.html).

mod error;
mod memory;
pub mod mock;
mod vm;

use std::{
    collections::HashMap,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::{Sink, SinkExt, Stream, StreamExt, TryFutureExt};
use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::{Hash, SecureHash},
};
use mpz_garble_core::{msg::GarbleMessage, EqualityCheck};
use rand::thread_rng;
use utils_aio::expect_msg_or_err;

use crate::{
    config::{Role, Visibility},
    evaluator::{Evaluator, EvaluatorConfigBuilder},
    generator::{Generator, GeneratorConfigBuilder},
    internal_circuits::{build_otp_circuit, build_otp_shared_circuit},
    memory::ValueMemory,
    ot::{OTReceiveEncoding, OTSendEncoding, OTVerifyEncoding},
    value::ValueRef,
};

pub use error::{DEAPError, PeerEncodingsError};
pub use vm::{DEAPThread, DEAPVm, PeerEncodings};

use self::error::FinalizationError;

/// The DEAP protocol.
#[derive(Debug)]
pub struct DEAP {
    role: Role,
    gen: Generator,
    ev: Evaluator,
    state: Mutex<State>,
    finalized: bool,
}

#[derive(Debug, Default)]
struct State {
    memory: ValueMemory,

    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    ///
    /// Operation ID => Equality check decommitment
    eq_decommitments: HashMap<String, Decommitment<EqualityCheck>>,
    /// Equality check commitments from the leader
    ///
    /// Operation ID => (Expected eq. check value, hash commitment from leader)
    eq_commitments: HashMap<String, (EqualityCheck, Hash)>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    ///
    /// Operation ID => GC output hash decommitment
    proof_decommitments: HashMap<String, Decommitment<Hash>>,
    /// Proof commitments from the leader
    ///
    /// Operation ID => (Expected GC output hash, hash commitment from leader)
    proof_commitments: HashMap<String, (Hash, Hash)>,
}

struct FinalizedState {
    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    eq_decommitments: Vec<(String, Decommitment<EqualityCheck>)>,
    /// Equality check commitments from the leader
    eq_commitments: Vec<(String, (EqualityCheck, Hash))>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    proof_decommitments: Vec<(String, Decommitment<Hash>)>,
    /// Proof commitments from the leader
    proof_commitments: Vec<(String, (Hash, Hash))>,
}

impl DEAP {
    /// Creates a new DEAP protocol instance.
    pub fn new(role: Role, encoder_seed: [u8; 32]) -> Self {
        let mut gen_config_builder = GeneratorConfigBuilder::default();
        let mut ev_config_builder = EvaluatorConfigBuilder::default();

        match role {
            Role::Leader => {
                // Sends commitments to output encodings.
                gen_config_builder.encoding_commitments();
                // Logs evaluated circuits and decodings.
                ev_config_builder.log_circuits().log_decodings();
            }
            Role::Follower => {
                // Expects commitments to output encodings.
                ev_config_builder.encoding_commitments();
            }
        }

        let gen_config = gen_config_builder.build().expect("config should be valid");
        let ev_config = ev_config_builder.build().expect("config should be valid");

        let gen = Generator::new(gen_config, encoder_seed);
        let ev = Evaluator::new(ev_config);

        Self {
            role,
            gen,
            ev,
            state: Mutex::new(State::default()),
            finalized: false,
        }
    }

    fn state(&self) -> impl DerefMut<Target = State> + '_ {
        self.state.lock().unwrap()
    }

    /// Performs pre-processing for executing the provided circuit.
    ///
    /// # Arguments
    ///
    /// * `circ` - The circuit to load.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs of the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    pub async fn load<T, U>(
        &self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
    {
        // Generate and receive concurrently.
        // Drop the encoded outputs, we don't need them here
        _ = futures::try_join!(
            self.gen
                .generate(circ.clone(), inputs, outputs, sink, false)
                .map_err(DEAPError::from),
            self.ev
                .receive_garbled_circuit(circ.clone(), inputs, outputs, stream)
                .map_err(DEAPError::from)
        )?;

        Ok(())
    }

    /// Executes a circuit.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    /// * `ot_send` - The OT sender.
    /// * `ot_recv` - The OT receiver.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute<T, U, OTS, OTR>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let assigned_values = self.state().memory.drain_assigned(inputs);

        let id_0 = format!("{}/0", id);
        let id_1 = format!("{}/1", id);

        let (gen_id, ev_id) = match self.role {
            Role::Leader => (id_0, id_1),
            Role::Follower => (id_1, id_0),
        };

        // Setup inputs concurrently.
        futures::try_join!(
            self.gen
                .setup_assigned_values(&gen_id, &assigned_values, sink, ot_send)
                .map_err(DEAPError::from),
            self.ev
                .setup_assigned_values(&ev_id, &assigned_values, stream, ot_recv)
                .map_err(DEAPError::from)
        )?;

        // Generate and evaluate concurrently.
        // Drop the encoded outputs, we don't need them here
        _ = futures::try_join!(
            self.gen
                .generate(circ.clone(), inputs, outputs, sink, false)
                .map_err(DEAPError::from),
            self.ev
                .evaluate(circ.clone(), inputs, outputs, stream)
                .map_err(DEAPError::from)
        )?;

        Ok(())
    }

    /// Proves the output of a circuit to the other party.
    ///
    /// # Notes
    ///
    /// This function can only be called by the leader.
    ///
    /// This function does _not_ prove the output right away,
    /// instead the proof is committed to and decommitted later during
    /// the call to [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    /// * `ot_recv` - The OT receiver.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_prove<S, OTR>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        stream: &mut S,
        ot_recv: &OTR,
    ) -> Result<(), DEAPError>
    where
        S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OTR: OTReceiveEncoding,
    {
        if matches!(self.role, Role::Follower) {
            return Err(DEAPError::RoleError(
                "DEAP follower can not act as the prover".to_string(),
            ))?;
        }

        let assigned_values = self.state().memory.drain_assigned(inputs);

        // The prover only acts as the evaluator for ZKPs instead of
        // dual-execution.
        self.ev
            .setup_assigned_values(id, &assigned_values, stream, ot_recv)
            .map_err(DEAPError::from)
            .await?;

        self.ev
            .evaluate(circ, inputs, outputs, stream)
            .map_err(DEAPError::from)
            .await?;

        Ok(())
    }

    /// Executes the circuit where only the follower is the generator.
    ///
    /// # Notes
    ///
    /// This function can only be called by the follower.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the circuit.
    /// * `circ` - The circuit to execute.
    /// * `inputs` - The inputs to the circuit.
    /// * `outputs` - The outputs to the circuit.
    /// * `sink` - The sink to send messages to.
    /// * `ot_send` - The OT sender.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_verify<T, OTS>(
        &self,
        id: &str,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        sink: &mut T,
        ot_send: &OTS,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        OTS: OTSendEncoding,
    {
        if matches!(self.role, Role::Leader) {
            return Err(DEAPError::RoleError(
                "DEAP leader can not act as the verifier".to_string(),
            ))?;
        }

        let assigned_values = self.state().memory.drain_assigned(inputs);

        // The verifier only acts as the generator for ZKPs instead of
        // dual-execution.
        self.gen
            .setup_assigned_values(id, &assigned_values, sink, ot_send)
            .map_err(DEAPError::from)
            .await?;

        self.gen
            .generate(circ.clone(), inputs, outputs, sink, false)
            .map_err(DEAPError::from)
            .await?;

        Ok(())
    }

    /// Sends a commitment to the provided values, proving them to the follower upon finalization.
    pub async fn defer_prove<S: Sink<GarbleMessage, Error = std::io::Error> + Unpin>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut S,
    ) -> Result<(), DEAPError> {
        let encoded_values = self.ev.get_encodings(values)?;

        let encoding_digest = encoded_values.hash();
        let (decommitment, commitment) = encoding_digest.hash_commit();

        // Store output proof decommitment until finalization
        self.state()
            .proof_decommitments
            .insert(id.to_string(), decommitment);

        sink.send(GarbleMessage::HashCommitment(commitment)).await?;

        Ok(())
    }

    /// Receives a commitment to the provided values, and stores it until finalization.
    ///
    /// # Notes
    ///
    /// This function does not verify the values until [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the operation
    /// * `values` - The values to receive a commitment to
    /// * `expected_values` - The expected values which will be verified against the commitment
    /// * `stream` - The stream to receive messages from
    pub async fn defer_verify<S: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin>(
        &self,
        id: &str,
        values: &[ValueRef],
        expected_values: &[Value],
        stream: &mut S,
    ) -> Result<(), DEAPError> {
        let encoded_values = self.gen.get_encodings(values)?;

        let expected_values = expected_values
            .iter()
            .zip(encoded_values)
            .map(|(expected, encoded)| encoded.select(expected.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let expected_digest = expected_values.hash();

        let commitment = expect_msg_or_err!(stream, GarbleMessage::HashCommitment)?;

        // Store commitment to proof until finalization
        self.state()
            .proof_commitments
            .insert(id.to_string(), (expected_digest, commitment));

        Ok(())
    }

    /// Decodes the provided values, revealing the plaintext value to both parties.
    ///
    /// # Notes
    ///
    /// The dual-execution equality check is deferred until [`finalize`](Self::finalize).
    ///
    /// For the leader, the authenticity of the decoded values is guaranteed. Conversely,
    /// the follower can not be sure that the values are authentic until the equality check
    /// is performed later during [`finalize`](Self::finalize).
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the operation
    /// * `values` - The values to decode
    /// * `sink` - The sink to send messages to.
    /// * `stream` - The stream to receive messages from.
    pub async fn decode<T, U>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
    {
        let full = values
            .iter()
            .map(|value| {
                self.gen
                    .get_encoding(value)
                    .ok_or(DEAPError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let active = values
            .iter()
            .map(|value| {
                self.ev
                    .get_encoding(value)
                    .ok_or(DEAPError::MissingEncoding(value.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Decode concurrently.
        let (_, purported_values) = futures::try_join!(
            self.gen.decode(values, sink).map_err(DEAPError::from),
            self.ev.decode(values, stream).map_err(DEAPError::from),
        )?;

        let eq_check = EqualityCheck::new(
            &full,
            &active,
            &purported_values,
            match self.role {
                Role::Leader => false,
                Role::Follower => true,
            },
        );

        let output = match self.role {
            Role::Leader => {
                let (decommitment, commit) = eq_check.hash_commit();

                // Store equality check decommitment until finalization
                self.state()
                    .eq_decommitments
                    .insert(id.to_string(), decommitment);

                // Send commitment to equality check to follower
                sink.send(GarbleMessage::HashCommitment(commit)).await?;

                // Receive the active encoded outputs from the follower
                let active = expect_msg_or_err!(stream, GarbleMessage::ActiveValues)?;

                // Authenticate and decode values
                active
                    .into_iter()
                    .zip(full)
                    .map(|(active, full)| full.decode(&active))
                    .collect::<Result<Vec<_>, _>>()?
            }
            Role::Follower => {
                // Receive equality check commitment from leader
                let commit = expect_msg_or_err!(stream, GarbleMessage::HashCommitment)?;

                // Store equality check commitment until finalization
                self.state()
                    .eq_commitments
                    .insert(id.to_string(), (eq_check, commit));

                // Send active encoded values to leader
                sink.send(GarbleMessage::ActiveValues(active)).await?;

                // Assume purported values are correct until finalization
                purported_values
            }
        };

        Ok(output)
    }

    pub(crate) async fn decode_private<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let (((otp_refs, otp_typs), otp_values), mask_refs): (((Vec<_>, Vec<_>), Vec<_>), Vec<_>) = {
            let mut state = self.state();

            values
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    let (otp_ref, otp_value) =
                        state.new_private_otp(&format!("{id}/{idx}/otp"), value);
                    let otp_typ = otp_value.value_type();
                    let mask_ref = state.new_output_mask(&format!("{id}/{idx}/mask"), value);
                    self.gen.generate_input_encoding(&otp_ref, &otp_typ);
                    (((otp_ref, otp_typ), otp_value), mask_ref)
                })
                .unzip()
        };

        // Apply OTPs to values
        let circ = build_otp_circuit(&otp_typs);

        let inputs = values
            .iter()
            .zip(otp_refs.iter())
            .flat_map(|(value, otp)| [value, otp])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id, circ, &inputs, &mask_refs, sink, stream, ot_send, ot_recv,
        )
        .await?;

        // Decode masked values
        let masked_values = self.decode(id, &mask_refs, sink, stream).await?;

        // Remove OTPs, returning plaintext values
        Ok(masked_values
            .into_iter()
            .zip(otp_values)
            .map(|(masked, otp)| (masked ^ otp).expect("values are same type"))
            .collect())
    }

    pub(crate) async fn decode_blind<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<(), DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        let ((otp_refs, otp_typs), mask_refs): ((Vec<_>, Vec<_>), Vec<_>) = {
            let mut state = self.state();

            values
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    let (otp_ref, otp_typ) = state.new_blind_otp(&format!("{id}/{idx}/otp"), value);
                    let mask_ref = state.new_output_mask(&format!("{id}/{idx}/mask"), value);
                    self.gen.generate_input_encoding(&otp_ref, &otp_typ);
                    ((otp_ref, otp_typ), mask_ref)
                })
                .unzip()
        };

        // Apply OTPs to values
        let circ = build_otp_circuit(&otp_typs);

        let inputs = values
            .iter()
            .zip(otp_refs.iter())
            .flat_map(|(value, otp)| [value, otp])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id, circ, &inputs, &mask_refs, sink, stream, ot_send, ot_recv,
        )
        .await?;

        // Discard masked values
        _ = self.decode(id, &mask_refs, sink, stream).await?;

        Ok(())
    }

    pub(crate) async fn decode_shared<T, U, OTS, OTR>(
        &self,
        id: &str,
        values: &[ValueRef],
        sink: &mut T,
        stream: &mut U,
        ot_send: &OTS,
        ot_recv: &OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OTS: OTSendEncoding,
        OTR: OTReceiveEncoding,
    {
        #[allow(clippy::type_complexity)]
        let ((((otp_0_refs, otp_1_refs), otp_typs), otp_values), mask_refs): (
            (((Vec<_>, Vec<_>), Vec<_>), Vec<_>),
            Vec<_>,
        ) = {
            let mut state = self.state();

            values
                .iter()
                .enumerate()
                .map(|(idx, value)| {
                    let (otp_0_ref, otp_1_ref, otp_value, otp_typ) = match self.role {
                        Role::Leader => {
                            let (otp_0_ref, otp_value) =
                                state.new_private_otp(&format!("{id}/{idx}/otp_0"), value);
                            let (otp_1_ref, otp_typ) =
                                state.new_blind_otp(&format!("{id}/{idx}/otp_1"), value);
                            (otp_0_ref, otp_1_ref, otp_value, otp_typ)
                        }
                        Role::Follower => {
                            let (otp_0_ref, otp_typ) =
                                state.new_blind_otp(&format!("{id}/{idx}/otp_0"), value);
                            let (otp_1_ref, otp_value) =
                                state.new_private_otp(&format!("{id}/{idx}/otp_1"), value);
                            (otp_0_ref, otp_1_ref, otp_value, otp_typ)
                        }
                    };
                    let mask_ref = state.new_output_mask(&format!("{id}/{idx}/mask"), value);
                    self.gen.generate_input_encoding(&otp_0_ref, &otp_typ);
                    self.gen.generate_input_encoding(&otp_1_ref, &otp_typ);
                    ((((otp_0_ref, otp_1_ref), otp_typ), otp_value), mask_ref)
                })
                .unzip()
        };

        // Apply OTPs to values
        let circ = build_otp_shared_circuit(&otp_typs);

        let inputs = values
            .iter()
            .zip(&otp_0_refs)
            .zip(&otp_1_refs)
            .flat_map(|((value, otp_0), otp_1)| [value, otp_0, otp_1])
            .cloned()
            .collect::<Vec<_>>();

        self.execute(
            id, circ, &inputs, &mask_refs, sink, stream, ot_send, ot_recv,
        )
        .await?;

        // Decode masked values
        let masked_values = self.decode(id, &mask_refs, sink, stream).await?;

        match self.role {
            Role::Leader => {
                // Leader removes his OTP
                Ok(masked_values
                    .into_iter()
                    .zip(otp_values)
                    .map(|(masked, otp)| (masked ^ otp).expect("values are the same type"))
                    .collect::<Vec<_>>())
            }
            Role::Follower => {
                // Follower uses his OTP as his share
                Ok(otp_values)
            }
        }
    }

    /// Finalize the DEAP instance.
    ///
    /// If this instance is the leader, this function will return the follower's
    /// encoder seed.
    ///
    /// # Notes
    ///
    /// **This function will reveal all private inputs of the follower.**
    ///
    /// The follower reveals all his secrets to the leader, who can then verify
    /// that all oblivious transfers, circuit garbling, and value decoding was
    /// performed correctly.
    ///
    /// After the leader has verified everything, they decommit to all equality checks
    /// and ZK proofs from the session. The follower then verifies the decommitments
    /// and that all the equality checks and proofs were performed as expected.
    ///
    /// # Arguments
    ///
    /// - `channel` - The channel to communicate with the other party
    /// - `ot` - The OT verifier to use
    pub async fn finalize<
        T: Sink<GarbleMessage, Error = std::io::Error> + Unpin,
        U: Stream<Item = Result<GarbleMessage, std::io::Error>> + Unpin,
        OT: OTVerifyEncoding,
    >(
        &mut self,
        sink: &mut T,
        stream: &mut U,
        ot: &OT,
    ) -> Result<Option<[u8; 32]>, DEAPError> {
        if self.finalized {
            return Err(FinalizationError::AlreadyFinalized)?;
        } else {
            self.finalized = true;
        }

        let FinalizedState {
            eq_commitments,
            eq_decommitments,
            proof_commitments,
            proof_decommitments,
        } = self.state().finalize_state();

        match self.role {
            Role::Leader => {
                // Receive the encoder seed from the follower.
                let encoder_seed = expect_msg_or_err!(stream, GarbleMessage::EncoderSeed)?;

                let encoder_seed: [u8; 32] = encoder_seed
                    .try_into()
                    .map_err(|_| FinalizationError::InvalidEncoderSeed)?;

                // Verify all oblivious transfers, garbled circuits and decodings
                // sent by the follower.
                self.ev.verify(encoder_seed, ot).await?;

                // Reveal the equality check decommitments to the follower.
                sink.send(GarbleMessage::EqualityCheckDecommitments(
                    eq_decommitments
                        .into_iter()
                        .map(|(_, decommitment)| decommitment)
                        .collect(),
                ))
                .await?;

                // Reveal the proof decommitments to the follower.
                sink.send(GarbleMessage::ProofDecommitments(
                    proof_decommitments
                        .into_iter()
                        .map(|(_, decommitment)| decommitment)
                        .collect(),
                ))
                .await?;

                Ok(Some(encoder_seed))
            }
            Role::Follower => {
                let encoder_seed = self.gen.seed();

                sink.send(GarbleMessage::EncoderSeed(encoder_seed.to_vec()))
                    .await?;

                // Receive the equality check decommitments from the leader.
                let eq_decommitments =
                    expect_msg_or_err!(stream, GarbleMessage::EqualityCheckDecommitments)?;

                // Receive the proof decommitments from the leader.
                let proof_decommitments =
                    expect_msg_or_err!(stream, GarbleMessage::ProofDecommitments)?;

                // Verify all equality checks.
                for (decommitment, (_, (expected_check, commitment))) in
                    eq_decommitments.iter().zip(eq_commitments.iter())
                {
                    decommitment
                        .verify(commitment)
                        .map_err(FinalizationError::from)?;

                    if decommitment.data() != expected_check {
                        return Err(FinalizationError::InvalidEqualityCheck)?;
                    }
                }

                // Verify all proofs.
                for (decommitment, (_, (expected_digest, commitment))) in
                    proof_decommitments.iter().zip(proof_commitments.iter())
                {
                    decommitment
                        .verify(commitment)
                        .map_err(FinalizationError::from)?;

                    if decommitment.data() != expected_digest {
                        return Err(FinalizationError::InvalidProof)?;
                    }
                }

                Ok(None)
            }
        }
    }

    /// Returns a reference to the evaluator.
    pub(crate) fn ev(&self) -> &Evaluator {
        &self.ev
    }
}

impl State {
    pub(crate) fn new_private_otp(&mut self, id: &str, value_ref: &ValueRef) -> (ValueRef, Value) {
        let typ = self.memory.get_value_type(value_ref);
        let value = Value::random(&mut thread_rng(), &typ);

        let value_ref = self
            .memory
            .new_input(id, typ, Visibility::Private)
            .expect("otp id is unique");

        self.memory
            .assign(&value_ref, value.clone())
            .expect("value should assign");

        (value_ref, value)
    }

    pub(crate) fn new_blind_otp(
        &mut self,
        id: &str,
        value_ref: &ValueRef,
    ) -> (ValueRef, ValueType) {
        let typ = self.memory.get_value_type(value_ref);

        (
            self.memory
                .new_input(id, typ.clone(), Visibility::Blind)
                .expect("otp id is unique"),
            typ,
        )
    }

    pub(crate) fn new_output_mask(&mut self, id: &str, value_ref: &ValueRef) -> ValueRef {
        let typ = self.memory.get_value_type(value_ref);
        self.memory.new_output(id, typ).expect("mask id is unique")
    }

    /// Drain the states to be finalized.
    fn finalize_state(&mut self) -> FinalizedState {
        let (
            mut eq_decommitments,
            mut eq_commitments,
            mut proof_decommitments,
            mut proof_commitments,
        ) = {
            (
                self.eq_decommitments.drain().collect::<Vec<_>>(),
                self.eq_commitments.drain().collect::<Vec<_>>(),
                self.proof_decommitments.drain().collect::<Vec<_>>(),
                self.proof_commitments.drain().collect::<Vec<_>>(),
            )
        };

        // Sort the decommitments and commitments by id
        eq_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        eq_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_decommitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        proof_commitments.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        FinalizedState {
            eq_decommitments,
            eq_commitments,
            proof_decommitments,
            proof_commitments,
        }
    }
}

#[cfg(test)]
mod tests {
    use mpz_circuits::{circuits::AES128, ops::WrappingAdd, CircuitBuilder};
    use mpz_ot::ideal::ideal_ot_shared_pair;
    use utils_aio::duplex::MemoryDuplex;

    use crate::Memory;

    use super::*;

    fn adder_circ() -> Arc<Circuit> {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>();
        let b = builder.add_input::<u8>();

        let c = a.wrapping_add(b);

        builder.add_output(c);

        Arc::new(builder.build().unwrap())
    }

    #[tokio::test]
    async fn test_deap() {
        let (leader_channel, follower_channel) = MemoryDuplex::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = ideal_ot_shared_pair();
        let (follower_ot_send, leader_ot_recv) = ideal_ot_shared_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();

            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader.assign(&key_ref, key).unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();

            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower.assign(&msg_ref, msg).unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (leader_output, follower_output) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, follower_output);
    }

    #[tokio::test]
    async fn test_deap_load() {
        let (leader_channel, follower_channel) = MemoryDuplex::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = ideal_ot_shared_pair();
        let (follower_ot_send, leader_ot_recv) = ideal_ot_shared_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();

            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                leader
                    .load(
                        AES128.clone(),
                        &[key_ref.clone(), msg_ref.clone()],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                    )
                    .await
                    .unwrap();

                leader.assign(&key_ref, key).unwrap();

                leader
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();

            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                follower
                    .load(
                        AES128.clone(),
                        &[key_ref.clone(), msg_ref.clone()],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                    )
                    .await
                    .unwrap();

                follower.assign(&msg_ref, msg).unwrap();

                follower
                    .execute(
                        "test",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode("test", &[ciphertext_ref], &mut sink, &mut stream)
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (leader_output, follower_output) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, follower_output);
    }

    #[tokio::test]
    async fn test_deap_decode_private() {
        let (leader_channel, follower_channel) = MemoryDuplex::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = ideal_ot_shared_pair();
        let (follower_ot_send, leader_ot_recv) = ideal_ot_shared_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c: Value = (a + b).into();

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let circ = circ.clone();
            let a_ref = leader.new_private_input::<u8>("a").unwrap();
            let b_ref = leader.new_blind_input::<u8>("b").unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            leader.assign(&a_ref, a).unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_private(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();

            let a_ref = follower.new_blind_input::<u8>("a").unwrap();
            let b_ref = follower.new_private_input::<u8>("b").unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            follower.assign(&b_ref, b).unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .decode_blind(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();
            }
        };

        let (leader_output, _) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, vec![c]);
    }

    #[tokio::test]
    async fn test_deap_decode_shared() {
        let (leader_channel, follower_channel) = MemoryDuplex::<GarbleMessage>::new();
        let (leader_ot_send, follower_ot_recv) = ideal_ot_shared_pair();
        let (follower_ot_send, leader_ot_recv) = ideal_ot_shared_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c = a + b;

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let circ = circ.clone();
            let a_ref = leader.new_private_input::<u8>("a").unwrap();
            let b_ref = leader.new_blind_input::<u8>("b").unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            leader.assign(&a_ref, a).unwrap();

            async move {
                leader
                    .execute(
                        "test",
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_shared(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &leader_ot_send,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();

            let a_ref = follower.new_blind_input::<u8>("a").unwrap();
            let b_ref = follower.new_private_input::<u8>("b").unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            follower.assign(&b_ref, b).unwrap();

            async move {
                follower
                    .execute(
                        "test",
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode_shared(
                        "test",
                        &[c_ref],
                        &mut sink,
                        &mut stream,
                        &follower_ot_send,
                        &follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let (mut leader_output, mut follower_output) = tokio::join!(leader_fut, follower_fut);

        let leader_share: u8 = leader_output.pop().unwrap().try_into().unwrap();
        let follower_share: u8 = follower_output.pop().unwrap().try_into().unwrap();

        assert_eq!((leader_share ^ follower_share), c);
    }

    #[tokio::test]
    async fn test_deap_zk_pass() {
        run_zk(
            [42u8; 16],
            [69u8; 16],
            [
                235u8, 22, 253, 138, 102, 20, 139, 100, 252, 153, 244, 111, 84, 116, 199, 75,
            ],
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_deap_zk_fail() {
        run_zk(
            [42u8; 16],
            [69u8; 16],
            // wrong ciphertext
            [
                235u8, 22, 253, 138, 102, 20, 139, 100, 252, 153, 244, 111, 84, 116, 199, 76,
            ],
        )
        .await;
    }

    async fn run_zk(key: [u8; 16], msg: [u8; 16], expected_ciphertext: [u8; 16]) {
        let (leader_channel, follower_channel) = MemoryDuplex::<GarbleMessage>::new();
        let (_, follower_ot_recv) = ideal_ot_shared_pair();
        let (follower_ot_send, leader_ot_recv) = ideal_ot_shared_pair();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let leader_fut = {
            let (mut sink, mut stream) = leader_channel.split();
            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader.assign(&key_ref, key).unwrap();

            async move {
                leader
                    .execute_prove(
                        "test0",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut stream,
                        &leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .defer_prove("test1", &[ciphertext_ref], &mut sink)
                    .await
                    .unwrap();

                leader
                    .finalize(&mut sink, &mut stream, &leader_ot_recv)
                    .await
                    .unwrap();
            }
        };

        let follower_fut = {
            let (mut sink, mut stream) = follower_channel.split();
            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower.assign(&msg_ref, msg).unwrap();

            async move {
                follower
                    .execute_verify(
                        "test0",
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut sink,
                        &follower_ot_send,
                    )
                    .await
                    .unwrap();

                follower
                    .defer_verify(
                        "test1",
                        &[ciphertext_ref],
                        &[expected_ciphertext.into()],
                        &mut stream,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut sink, &mut stream, &follower_ot_recv)
                    .await
                    .unwrap();
            }
        };

        futures::join!(leader_fut, follower_fut);
    }
}
