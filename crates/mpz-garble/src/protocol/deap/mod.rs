//! An implementation of the Dual-execution with Asymmetric Privacy (DEAP) protocol.
//!
//! For more information, see the [DEAP specification](https://docs.tlsnotary.org/mpc/deap.html).

mod error;
mod memory;
pub mod mock;
mod vm;

use std::{
    collections::HashMap,
    mem,
    ops::DerefMut,
    sync::{Arc, Mutex},
};

use futures::TryFutureExt;
use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_common::{try_join, Context, Counter, ThreadId};
use mpz_core::{
    commit::{Decommitment, HashCommit},
    hash::{Hash, SecureHash},
};
use mpz_garble_core::EqualityCheck;
use rand::thread_rng;
use serio::{stream::IoStreamExt, SinkExt};

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
pub use vm::{DEAPThread, PeerEncodings};

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
    logs: HashMap<ThreadId, ThreadLog>,
}

#[derive(Debug, Default)]
struct ThreadLog {
    /// A counter for the number of operations performed by the thread.
    operation_counter: Counter,
    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    eq_decommitments: Vec<Decommitment<EqualityCheck>>,
    /// Equality check commitments from the leader
    ///
    /// (Expected eq. check value, hash commitment from leader)
    eq_commitments: Vec<(EqualityCheck, Hash)>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    ///
    /// GC output hash decommitment
    proof_decommitments: Vec<Decommitment<Hash>>,
    /// Proof commitments from the leader
    ///
    /// (Expected GC output hash, hash commitment from leader)
    proof_commitments: Vec<(Hash, Hash)>,
}

#[derive(Default)]
struct FinalizedState {
    /// Equality check decommitments withheld by the leader
    /// prior to finalization
    eq_decommitments: Vec<Decommitment<EqualityCheck>>,
    /// Equality check commitments from the leader
    ///
    /// (Expected eq. check value, hash commitment from leader)
    eq_commitments: Vec<(EqualityCheck, Hash)>,
    /// Proof decommitments withheld by the leader
    /// prior to finalization
    ///
    /// GC output hash decommitment
    proof_decommitments: Vec<Decommitment<Hash>>,
    /// Proof commitments from the leader
    ///
    /// (Expected GC output hash, hash commitment from leader)
    proof_commitments: Vec<(Hash, Hash)>,
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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn load<Ctx: Context>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), DEAPError> {
        // Generate and receive concurrently.
        // Drop the encoded outputs, we don't need them here
        match self.role {
            Role::Leader => {
                try_join!(
                    ctx,
                    self.gen
                        .generate(ctx, circ.clone(), inputs, outputs, false)
                        .map_err(DEAPError::from),
                    self.ev
                        .receive_garbled_circuit(ctx, circ.clone(), inputs, outputs)
                        .map_err(DEAPError::from)
                )??;
            }
            Role::Follower => {
                try_join!(
                    ctx,
                    self.ev
                        .receive_garbled_circuit(ctx, circ.clone(), inputs, outputs)
                        .map_err(DEAPError::from),
                    self.gen
                        .generate(ctx, circ.clone(), inputs, outputs, false)
                        .map_err(DEAPError::from)
                )??;
            }
        }

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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn execute<Ctx, OTS, OTR>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        ot_send: &mut OTS,
        ot_recv: &mut OTR,
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
        OTS: OTSendEncoding<Ctx> + Send,
        OTR: OTReceiveEncoding<Ctx> + Send,
    {
        let assigned_values = self.state().memory.drain_assigned(inputs);

        match self.role {
            Role::Leader => {
                try_join! {
                    ctx,
                    async {
                        self.gen
                            .setup_assigned_values(ctx, &assigned_values, ot_send)
                            .await?;

                        self.gen
                            .generate(ctx, circ.clone(), inputs, outputs, false)
                            .await
                            .map_err(DEAPError::from)
                    },
                    async {
                        self.ev
                            .setup_assigned_values(ctx, &assigned_values, ot_recv)
                            .await?;

                        self.ev
                            .evaluate(ctx, circ.clone(), inputs, outputs)
                            .await
                            .map_err(DEAPError::from)
                    }
                }??;
            }
            Role::Follower => {
                try_join! {
                    ctx,
                    async {
                        self.ev
                            .setup_assigned_values(ctx, &assigned_values, ot_recv)
                            .await?;

                        self.ev
                            .evaluate(ctx, circ.clone(), inputs, outputs)
                            .await
                            .map_err(DEAPError::from)
                    },
                    async {
                        self.gen
                            .setup_assigned_values(ctx, &assigned_values, ot_send)
                            .await?;

                        self.gen
                            .generate(ctx, circ.clone(), inputs, outputs, false)
                            .await
                            .map_err(DEAPError::from)
                    }
                }??;
            }
        };

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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn execute_prove<Ctx, OTR>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        ot_recv: &mut OTR,
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
        OTR: OTReceiveEncoding<Ctx> + Send,
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
            .setup_assigned_values(ctx, &assigned_values, ot_recv)
            .map_err(DEAPError::from)
            .await?;

        self.ev
            .evaluate(ctx, circ, inputs, outputs)
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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn execute_verify<Ctx, OTS>(
        &self,
        ctx: &mut Ctx,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        ot_send: &mut OTS,
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
        OTS: OTSendEncoding<Ctx> + Send,
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
            .setup_assigned_values(ctx, &assigned_values, ot_send)
            .map_err(DEAPError::from)
            .await?;

        self.gen
            .generate(ctx, circ.clone(), inputs, outputs, false)
            .map_err(DEAPError::from)
            .await?;

        Ok(())
    }

    /// Sends a commitment to the provided values, proving them to the follower upon finalization.
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn defer_prove<Ctx>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
    {
        let encoded_values = self.ev.get_encodings(values)?;

        let encoding_digest = encoded_values.hash();
        let (decommitment, commitment) = encoding_digest.hash_commit();

        // Store output proof decommitment until finalization
        self.state()
            .log(ctx.id())
            .proof_decommitments
            .push(decommitment);

        ctx.io_mut().send(commitment).await?;

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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn defer_verify<Ctx>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
        expected_values: &[Value],
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
    {
        let encoded_values = self.gen.get_encodings(values)?;

        let expected_values = expected_values
            .iter()
            .zip(encoded_values)
            .map(|(expected, encoded)| encoded.select(expected.clone()))
            .collect::<Result<Vec<_>, _>>()?;

        let expected_digest = expected_values.hash();

        let commitment: Hash = ctx.io_mut().expect_next().await?;

        // Store commitment to proof until finalization
        self.state()
            .log(ctx.id())
            .proof_commitments
            .push((expected_digest, commitment));

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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn decode<Ctx>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
    ) -> Result<Vec<Value>, DEAPError>
    where
        Ctx: Context,
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
        let purported_values = match self.role {
            Role::Leader => {
                let (_, purported_values) = try_join!(
                    ctx,
                    self.gen.decode(ctx, values).map_err(DEAPError::from),
                    self.ev.decode(ctx, values).map_err(DEAPError::from)
                )??;
                purported_values
            }
            Role::Follower => {
                let (purported_values, _) = try_join!(
                    ctx,
                    self.ev.decode(ctx, values).map_err(DEAPError::from),
                    self.gen.decode(ctx, values).map_err(DEAPError::from)
                )??;
                purported_values
            }
        };

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
                    .log(ctx.id())
                    .eq_decommitments
                    .push(decommitment);

                // Send commitment to equality check to follower
                ctx.io_mut().send(commit).await?;

                // Receive the active encoded outputs from the follower
                let active: Vec<_> = ctx.io_mut().expect_next().await?;

                // Authenticate and decode values
                active
                    .into_iter()
                    .zip(full)
                    .map(|(active, full)| full.decode(&active))
                    .collect::<Result<Vec<_>, _>>()?
            }
            Role::Follower => {
                // Receive equality check commitment from leader
                let commit: Hash = ctx.io_mut().expect_next().await?;

                // Store equality check commitment until finalization
                self.state()
                    .log(ctx.id())
                    .eq_commitments
                    .push((eq_check, commit));

                // Send active encoded values to leader
                ctx.io_mut().send(active).await?;

                // Assume purported values are correct until finalization
                purported_values
            }
        };

        Ok(output)
    }

    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub(crate) async fn decode_private<Ctx, OTS, OTR>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
        ot_send: &mut OTS,
        ot_recv: &mut OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        Ctx: Context,
        OTS: OTSendEncoding<Ctx> + Send,
        OTR: OTReceiveEncoding<Ctx> + Send,
    {
        let id = self.state().log(ctx.id()).operation_counter.next();
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

        self.execute(ctx, circ, &inputs, &mask_refs, ot_send, ot_recv)
            .await?;

        // Decode masked values
        let masked_values = self.decode(ctx, &mask_refs).await?;

        // Remove OTPs, returning plaintext values
        Ok(masked_values
            .into_iter()
            .zip(otp_values)
            .map(|(masked, otp)| (masked ^ otp).expect("values are same type"))
            .collect())
    }

    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub(crate) async fn decode_blind<Ctx, OTS, OTR>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
        ot_send: &mut OTS,
        ot_recv: &mut OTR,
    ) -> Result<(), DEAPError>
    where
        Ctx: Context,
        OTS: OTSendEncoding<Ctx> + Send,
        OTR: OTReceiveEncoding<Ctx> + Send,
    {
        let id = self.state().log(ctx.id()).operation_counter.next();
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

        self.execute(ctx, circ, &inputs, &mask_refs, ot_send, ot_recv)
            .await?;

        // Discard masked values
        _ = self.decode(ctx, &mask_refs).await?;

        Ok(())
    }

    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub(crate) async fn decode_shared<Ctx, OTS, OTR>(
        &self,
        ctx: &mut Ctx,
        values: &[ValueRef],
        ot_send: &mut OTS,
        ot_recv: &mut OTR,
    ) -> Result<Vec<Value>, DEAPError>
    where
        Ctx: Context,
        OTS: OTSendEncoding<Ctx> + Send,
        OTR: OTReceiveEncoding<Ctx> + Send,
    {
        let id = self.state().log(ctx.id()).operation_counter.next();
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

        self.execute(ctx, circ, &inputs, &mask_refs, ot_send, ot_recv)
            .await?;

        // Decode masked values
        let masked_values = self.decode(ctx, &mask_refs).await?;

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
    #[tracing::instrument(fields(role = %self.role, thread = %ctx.id()), skip_all)]
    pub async fn finalize<Ctx, OT>(
        &mut self,
        ctx: &mut Ctx,
        ot: &mut OT,
    ) -> Result<Option<[u8; 32]>, DEAPError>
    where
        Ctx: Context,
        OT: OTVerifyEncoding<Ctx>,
    {
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
                let encoder_seed: [u8; 32] = ctx.io_mut().expect_next().await?;

                // Verify all oblivious transfers, garbled circuits and decodings
                // sent by the follower.
                self.ev.verify(ctx, encoder_seed, ot).await?;

                // Reveal the equality checks and proofs to the follower.
                ctx.io_mut().feed(eq_decommitments).await?;
                ctx.io_mut().send(proof_decommitments).await?;

                Ok(Some(encoder_seed))
            }
            Role::Follower => {
                let encoder_seed: [u8; 32] = self
                    .gen
                    .seed()
                    .try_into()
                    .expect("encoder seed is 32 bytes");

                ctx.io_mut().send(encoder_seed).await?;

                // Receive the equality checks and proofs from the leader.
                let eq_decommitments: Vec<Decommitment<EqualityCheck>> =
                    ctx.io_mut().expect_next().await?;
                let proof_decommitments: Vec<Decommitment<Hash>> =
                    ctx.io_mut().expect_next().await?;

                // Verify all equality checks.
                for (decommitment, (expected_check, commitment)) in
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
                for (decommitment, (expected_digest, commitment)) in
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
    fn log(&mut self, id: &ThreadId) -> &mut ThreadLog {
        self.logs.entry(id.clone()).or_default()
    }

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
        let mut logs = mem::take(&mut self.logs).into_iter().collect::<Vec<_>>();
        logs.sort_by_cached_key(|(id, _)| id.clone());

        logs.into_iter()
            .fold(FinalizedState::default(), |mut state, (_, log)| {
                let ThreadLog {
                    eq_commitments,
                    eq_decommitments,
                    proof_commitments,
                    proof_decommitments,
                    ..
                } = log;

                state.eq_commitments.extend(eq_commitments);
                state.eq_decommitments.extend(eq_decommitments);
                state.proof_commitments.extend(proof_commitments);
                state.proof_decommitments.extend(proof_decommitments);

                state
            })
    }
}

#[cfg(test)]
mod tests {
    use mpz_circuits::{circuits::AES128, ops::WrappingAdd, CircuitBuilder};
    use mpz_common::executor::test_st_executor;
    use mpz_core::Block;
    use mpz_ot::ideal::ot::ideal_ot;

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
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut leader_ot_send, mut follower_ot_recv) = ideal_ot();
        let (mut follower_ot_send, mut leader_ot_recv) = ideal_ot();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader.assign(&key_ref, key).unwrap();

            async move {
                leader
                    .execute(
                        &mut ctx_a,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader.decode(&mut ctx_a, &[ciphertext_ref]).await.unwrap();

                leader
                    .finalize(&mut ctx_a, &mut leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower.assign(&msg_ref, msg).unwrap();

            async move {
                follower
                    .execute(
                        &mut ctx_b,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode(&mut ctx_b, &[ciphertext_ref])
                    .await
                    .unwrap();

                follower
                    .finalize(&mut ctx_b, &mut follower_ot_recv)
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
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut leader_ot_send, mut follower_ot_recv) = ideal_ot();
        let (mut follower_ot_send, mut leader_ot_recv) = ideal_ot();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                leader
                    .load(
                        &mut ctx_a,
                        AES128.clone(),
                        &[key_ref.clone(), msg_ref.clone()],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                leader.assign(&key_ref, key).unwrap();

                leader
                    .execute(
                        &mut ctx_a,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader.decode(&mut ctx_a, &[ciphertext_ref]).await.unwrap();

                leader
                    .finalize(&mut ctx_a, &mut leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                follower
                    .load(
                        &mut ctx_b,
                        AES128.clone(),
                        &[key_ref.clone(), msg_ref.clone()],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                follower.assign(&msg_ref, msg).unwrap();

                follower
                    .execute(
                        &mut ctx_b,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode(&mut ctx_b, &[ciphertext_ref])
                    .await
                    .unwrap();

                follower
                    .finalize(&mut ctx_b, &mut follower_ot_recv)
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
        tracing_subscriber::fmt::init();
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut leader_ot_send, mut follower_ot_recv) = ideal_ot();
        let (mut follower_ot_send, mut leader_ot_recv) = ideal_ot();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c: Value = (a + b).into();

        let leader_fut = {
            let circ = circ.clone();
            let a_ref = leader.new_private_input::<u8>("a").unwrap();
            let b_ref = leader.new_blind_input::<u8>("b").unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            leader.assign(&a_ref, a).unwrap();

            async move {
                leader
                    .execute(
                        &mut ctx_a,
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_private(
                        &mut ctx_a,
                        &[c_ref],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .finalize(&mut ctx_a, &mut leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let a_ref = follower.new_blind_input::<u8>("a").unwrap();
            let b_ref = follower.new_private_input::<u8>("b").unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            follower.assign(&b_ref, b).unwrap();

            async move {
                follower
                    .execute(
                        &mut ctx_b,
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await?;

                follower
                    .decode_blind(
                        &mut ctx_b,
                        &[c_ref],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await?;

                follower.finalize(&mut ctx_b, &mut follower_ot_recv).await?;

                Ok::<_, DEAPError>(())
            }
        };

        let (leader_output, _) = tokio::join!(leader_fut, follower_fut);

        assert_eq!(leader_output, vec![c]);
    }

    #[tokio::test]
    async fn test_deap_decode_shared() {
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut leader_ot_send, mut follower_ot_recv) = ideal_ot();
        let (mut follower_ot_send, mut leader_ot_recv) = ideal_ot();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let circ = adder_circ();

        let a = 1u8;
        let b = 2u8;
        let c = a + b;

        let leader_fut = {
            let circ = circ.clone();
            let a_ref = leader.new_private_input::<u8>("a").unwrap();
            let b_ref = leader.new_blind_input::<u8>("b").unwrap();
            let c_ref = leader.new_output::<u8>("c").unwrap();

            leader.assign(&a_ref, a).unwrap();

            async move {
                leader
                    .execute(
                        &mut ctx_a,
                        circ,
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = leader
                    .decode_shared(
                        &mut ctx_a,
                        &[c_ref],
                        &mut leader_ot_send,
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .finalize(&mut ctx_a, &mut leader_ot_recv)
                    .await
                    .unwrap();

                outputs
            }
        };

        let follower_fut = {
            let a_ref = follower.new_blind_input::<u8>("a").unwrap();
            let b_ref = follower.new_private_input::<u8>("b").unwrap();
            let c_ref = follower.new_output::<u8>("c").unwrap();

            follower.assign(&b_ref, b).unwrap();

            async move {
                follower
                    .execute(
                        &mut ctx_b,
                        circ.clone(),
                        &[a_ref, b_ref],
                        &[c_ref.clone()],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await
                    .unwrap();

                let outputs = follower
                    .decode_shared(
                        &mut ctx_b,
                        &[c_ref],
                        &mut follower_ot_send,
                        &mut follower_ot_recv,
                    )
                    .await
                    .unwrap();

                follower
                    .finalize(&mut ctx_b, &mut follower_ot_recv)
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
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (_, mut follower_ot_recv) = ideal_ot::<[Block; 2], _>();
        let (mut follower_ot_send, mut leader_ot_recv) = ideal_ot();

        let mut leader = DEAP::new(Role::Leader, [42u8; 32]);
        let mut follower = DEAP::new(Role::Follower, [69u8; 32]);

        let leader_fut = {
            let key_ref = leader.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader.assign(&key_ref, key).unwrap();

            async move {
                leader
                    .execute_prove(
                        &mut ctx_a,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut leader_ot_recv,
                    )
                    .await
                    .unwrap();

                leader
                    .defer_prove(&mut ctx_a, &[ciphertext_ref])
                    .await
                    .unwrap();

                leader
                    .finalize(&mut ctx_a, &mut leader_ot_recv)
                    .await
                    .unwrap();
            }
        };

        let follower_fut = {
            let key_ref = follower.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower.assign(&msg_ref, msg).unwrap();

            async move {
                follower
                    .execute_verify(
                        &mut ctx_b,
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                        &mut follower_ot_send,
                    )
                    .await
                    .unwrap();

                follower
                    .defer_verify(&mut ctx_b, &[ciphertext_ref], &[expected_ciphertext.into()])
                    .await
                    .unwrap();

                follower
                    .finalize(&mut ctx_b, &mut follower_ot_recv)
                    .await
                    .unwrap();
            }
        };

        futures::join!(leader_fut, follower_fut);
    }
}
