use std::{
    mem,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use futures::TryFutureExt;

use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_common::Context;
use mpz_garble_core::{encoding_state::Active, EncodedValue};

use crate::{
    config::{Role, Visibility},
    ot::{VerifiableOTReceiveEncoding, VerifiableOTSendEncoding},
    value::ValueRef,
    Decode, DecodeError, DecodePrivate, Execute, ExecutionError, Load, LoadError, Memory,
    MemoryError, Prove, ProveError, Thread, Verify, VerifyError,
};

use super::{
    error::{FinalizationError, PeerEncodingsError},
    DEAPError, DEAP,
};

#[derive(Debug)]
enum State {
    Main(Arc<DEAP>),
    Child(Weak<DEAP>),
    Finalized,
}

impl State {
    fn get(&self) -> Arc<DEAP> {
        match self {
            State::Main(deap) => deap.clone(),
            State::Child(deap) => deap.upgrade().expect("instance should not be dropped"),
            State::Finalized => panic!("instance is finalized"),
        }
    }

    fn is_finalized(&self) -> bool {
        matches!(self, State::Finalized)
    }
}

/// A DEAP thread.
#[derive(Debug)]
pub struct DEAPThread<Ctx, OTS, OTR> {
    /// The thread context.
    ctx: Ctx,
    /// OT sender.
    ot_send: OTS,
    /// OT receiver.
    ot_recv: OTR,
    state: State,
}

impl<Ctx, OTS, OTR> DEAPThread<Ctx, OTS, OTR> {
    /// Creates a new DEAP instance.
    pub fn new(role: Role, encoder_seed: [u8; 32], ctx: Ctx, ot_send: OTS, ot_recv: OTR) -> Self {
        Self {
            ctx,
            ot_send,
            ot_recv,
            state: State::Main(Arc::new(DEAP::new(role, encoder_seed))),
        }
    }

    /// Creates a new DEAP thread.
    pub fn new_thread(&self, ctx: Ctx, ot_send: OTS, ot_recv: OTR) -> Result<Self, DEAPError> {
        match &self.state {
            State::Main(state) => Ok(Self {
                ctx,
                ot_send,
                ot_recv,
                state: State::Child(Arc::downgrade(state)),
            }),
            State::Child(state) => Ok(Self {
                ctx,
                ot_send,
                ot_recv,
                state: State::Child(state.clone()),
            }),
            State::Finalized => Err(FinalizationError::AlreadyFinalized.into()),
        }
    }
}

impl<Ctx, OTS, OTR> DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTR: VerifiableOTReceiveEncoding<Ctx>,
{
    /// Finalizes the DEAP instance.
    ///
    /// If this instance is the leader, this function returns the follower's
    /// encoder seed.
    pub async fn finalize(&mut self) -> Result<Option<[u8; 32]>, DEAPError> {
        match mem::replace(&mut self.state, State::Finalized) {
            State::Main(deap) => {
                let mut deap =
                    Arc::try_unwrap(deap).expect("state should have only strong reference");
                deap.finalize(&mut self.ctx, &mut self.ot_recv).await
            }
            State::Child(_) => Err(FinalizationError::NotMainThread.into()),
            State::Finalized => return Err(FinalizationError::AlreadyFinalized.into()),
        }
    }
}

impl<Ctx, OTS, OTR> Thread for DEAPThread<Ctx, OTS, OTR> {}

impl<Ctx, OTS, OTR> Memory for DEAPThread<Ctx, OTS, OTR> {
    fn new_input_with_type(
        &self,
        id: &str,
        typ: ValueType,
        visibility: Visibility,
    ) -> Result<ValueRef, MemoryError> {
        self.state.get().new_input_with_type(id, typ, visibility)
    }

    fn new_output_with_type(&self, id: &str, typ: ValueType) -> Result<ValueRef, MemoryError> {
        self.state.get().new_output_with_type(id, typ)
    }

    fn assign(&self, value_ref: &ValueRef, value: impl Into<Value>) -> Result<(), MemoryError> {
        self.state.get().assign(value_ref, value)
    }

    fn assign_by_id(&self, id: &str, value: impl Into<Value>) -> Result<(), MemoryError> {
        self.state.get().assign_by_id(id, value)
    }

    fn get_value(&self, id: &str) -> Option<ValueRef> {
        self.state.get().get_value(id)
    }

    fn get_value_type(&self, value_ref: &ValueRef) -> ValueType {
        self.state.get().get_value_type(value_ref)
    }

    fn get_value_type_by_id(&self, id: &str) -> Option<ValueType> {
        self.state.get().get_value_type_by_id(id)
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> Load for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn load(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), LoadError> {
        self.state
            .get()
            .load(&mut self.ctx, circ, inputs, outputs)
            .map_err(LoadError::from)
            .await
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> Execute for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ExecutionError> {
        self.state
            .get()
            .execute(
                &mut self.ctx,
                circ,
                inputs,
                outputs,
                &mut self.ot_send,
                &mut self.ot_recv,
            )
            .map_err(ExecutionError::from)
            .await
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> Prove for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn execute_prove(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ProveError> {
        self.state
            .get()
            .execute_prove(&mut self.ctx, circ, inputs, outputs, &mut self.ot_recv)
            .map_err(ProveError::from)
            .await
    }

    async fn prove(&mut self, values: &[ValueRef]) -> Result<(), ProveError> {
        self.state
            .get()
            .defer_prove(&mut self.ctx, values)
            .map_err(ProveError::from)
            .await
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> Verify for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn execute_verify(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), VerifyError> {
        self.state
            .get()
            .execute_verify(&mut self.ctx, circ, inputs, outputs, &mut self.ot_send)
            .map_err(VerifyError::from)
            .await
    }

    async fn verify(
        &mut self,
        values: &[ValueRef],
        expected_values: &[Value],
    ) -> Result<(), VerifyError> {
        self.state
            .get()
            .defer_verify(&mut self.ctx, values, expected_values)
            .map_err(VerifyError::from)
            .await
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> Decode for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn decode(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.state
            .get()
            .decode(&mut self.ctx, values)
            .map_err(DecodeError::from)
            .await
    }
}

#[async_trait]
impl<Ctx, OTS, OTR> DecodePrivate for DEAPThread<Ctx, OTS, OTR>
where
    Ctx: Context,
    OTS: VerifiableOTSendEncoding<Ctx> + Send + Sync,
    OTR: VerifiableOTReceiveEncoding<Ctx> + Send + Sync,
{
    async fn decode_private(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.state
            .get()
            .decode_private(&mut self.ctx, values, &mut self.ot_send, &mut self.ot_recv)
            .map_err(DecodeError::from)
            .await
    }

    async fn decode_blind(&mut self, values: &[ValueRef]) -> Result<(), DecodeError> {
        self.state
            .get()
            .decode_blind(&mut self.ctx, values, &mut self.ot_send, &mut self.ot_recv)
            .map_err(DecodeError::from)
            .await
    }

    async fn decode_shared(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.state
            .get()
            .decode_shared(&mut self.ctx, values, &mut self.ot_send, &mut self.ot_recv)
            .map_err(DecodeError::from)
            .await
    }
}

/// This trait provides methods to get peer's encodings.
pub trait PeerEncodings {
    /// Returns the peer's encodings of the provided values.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not found or its encoding is not available.
    fn get_peer_encodings(
        &self,
        value_ids: &[&str],
    ) -> Result<Vec<EncodedValue<Active>>, PeerEncodingsError>;
}

impl<Ctx, OTS, OTR> PeerEncodings for DEAPThread<Ctx, OTS, OTR> {
    fn get_peer_encodings(
        &self,
        value_ids: &[&str],
    ) -> Result<Vec<EncodedValue<Active>>, PeerEncodingsError> {
        if self.state.is_finalized() {
            return Err(PeerEncodingsError::AlreadyFinalized);
        }

        let deap = self.state.get();

        value_ids
            .iter()
            .map(|id| {
                // get reference by id
                let value_ref = match deap.get_value(id) {
                    Some(v) => v,
                    None => return Err(PeerEncodingsError::ValueIdNotFound(id.to_string())),
                };
                // get encoding by reference
                match deap.ev().get_encoding(&value_ref) {
                    Some(e) => Ok(e),
                    None => Err(PeerEncodingsError::EncodingNotAvailable(value_ref)),
                }
            })
            .collect::<Result<Vec<_>, PeerEncodingsError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpz_circuits::circuits::AES128;

    use crate::protocol::deap::mock::create_mock_deap_vm;

    #[tokio::test]
    async fn test_vm() {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm();

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let key_ref = leader_vm.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader_vm.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader_vm.assign(&key_ref, key).unwrap();

            async {
                leader_vm
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                leader_vm.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        let follower_fut = {
            let key_ref = follower_vm.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower_vm.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower_vm.assign(&msg_ref, msg).unwrap();

            async {
                follower_vm
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                follower_vm.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        let (leader_result, follower_result) = futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_result, follower_result);

        let (leader_result, follower_result) =
            futures::join!(leader_vm.finalize(), follower_vm.finalize());

        leader_result.unwrap();
        follower_result.unwrap();
    }

    #[tokio::test]
    async fn test_peer_encodings() {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm();

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let key_ref = leader_vm.new_private_input::<[u8; 16]>("key").unwrap();
            let msg_ref = leader_vm.new_blind_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = leader_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

            leader_vm.assign(&key_ref, key).unwrap();

            // Encodings are not yet available because the circuit hasn't yet been executed
            let err = leader_vm.get_peer_encodings(&["msg"]).unwrap_err();
            assert!(matches!(err, PeerEncodingsError::EncodingNotAvailable(_)));

            async {
                leader_vm
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                leader_vm.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        let follower_fut = {
            let key_ref = follower_vm.new_blind_input::<[u8; 16]>("key").unwrap();
            let msg_ref = follower_vm.new_private_input::<[u8; 16]>("msg").unwrap();
            let ciphertext_ref = follower_vm.new_output::<[u8; 16]>("ciphertext").unwrap();

            follower_vm.assign(&msg_ref, msg).unwrap();

            async {
                follower_vm
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                follower_vm.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        // Execute the circuits
        _ = futures::join!(leader_fut, follower_fut);

        // Encodings must be available now
        assert!(leader_vm
            .get_peer_encodings(&["msg", "key", "ciphertext"])
            .is_ok());

        // A non-existent value id will cause an error
        let err = leader_vm
            .get_peer_encodings(&["msg", "random_id"])
            .unwrap_err();
        assert!(matches!(err, PeerEncodingsError::ValueIdNotFound(_)));

        // Trying to get encodings after finalization will cause an error
        _ = futures::join!(leader_vm.finalize(), follower_vm.finalize());
        let err = leader_vm.get_peer_encodings(&["msg"]).unwrap_err();
        assert!(matches!(err, PeerEncodingsError::AlreadyFinalized));
    }
}
