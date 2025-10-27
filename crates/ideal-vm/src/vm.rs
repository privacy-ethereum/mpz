use async_trait::async_trait;
use mpz_common::{Context, Flush};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFuture, Memory, Slice, View, binary::Binary};
use mpz_vm_core::{Call, Callable, Execute, Result, VmError};

use crate::store::Store;

/// Ideal VM.
#[derive(Debug)]
pub struct IdealVm {
    store: Store,
    call_stack: Vec<(Call, Slice)>,
}

impl IdealVm {
    /// Creates a new VM.
    pub fn new() -> Self {
        Self {
            store: Store::new(),
            call_stack: Vec::new(),
        }
    }
}

impl Default for IdealVm {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory<Binary> for IdealVm {
    type Error = VmError;

    fn is_alloc_raw(&self, slice: Slice) -> bool {
        self.store.is_alloc_raw(slice)
    }

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store.alloc_raw(size).map_err(VmError::memory)
    }

    fn is_assigned_raw(&self, slice: Slice) -> bool {
        self.store.is_assigned_raw(slice)
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store.assign_raw(slice, value).map_err(VmError::memory)
    }

    fn is_committed_raw(&self, slice: Slice) -> bool {
        self.store.is_committed_raw(slice)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit_raw(slice).map_err(VmError::memory)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store.get_raw(slice).map_err(VmError::memory)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(VmError::memory)
    }
}

impl View<Binary> for IdealVm {
    type Error = VmError;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(VmError::view)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice).map_err(VmError::view)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_blind_raw(slice).map_err(VmError::view)
    }
}

impl Callable<Binary> for IdealVm {
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let slice = self.store.alloc_output(call.circ().outputs().len());
        self.call_stack.push((call, slice));
        Ok(slice)
    }
}

#[async_trait]
impl Execute for IdealVm {
    fn wants_flush(&self) -> bool {
        self.store.wants_flush()
    }

    async fn flush(&mut self, ctx: &mut Context) -> Result<()> {
        if self.store.wants_flush() {
            self.store.flush(ctx).await.map_err(VmError::memory)?;
        }

        Ok(())
    }

    fn wants_preprocess(&self) -> bool {
        false
    }

    async fn preprocess(&mut self, _ctx: &mut Context) -> Result<()> {
        Ok(())
    }

    fn wants_execute(&self) -> bool {
        self.call_stack.iter().any(|(call, _)| {
            call.inputs()
                .iter()
                .all(|slice| self.store.is_committed_raw(*slice))
        })
    }

    async fn execute(&mut self, _ctx: &mut Context) -> Result<()> {
        while !self.call_stack.is_empty() {
            // Extract executable calls.
            let calls = self
                .call_stack
                .extract_if(.., |(call, _)| {
                    call.inputs()
                        .iter()
                        .all(|slice| self.store.is_committed_raw(*slice))
                })
                .collect::<Vec<(Call, Slice)>>();

            if calls.is_empty() {
                break;
            }

            for (call, output) in calls {
                // Collect input bits.
                let bits = call.inputs().iter().flat_map(|inp| {
                    self.store
                        .get_raw(*inp)
                        .expect("always Ok()")
                        .expect("input was set")
                        .into_iter()
                });

                let out = call.circ().evaluate(bits).expect("input count is correct");
                let bv: BitVec = out.into_iter().collect();

                self.store
                    .set_output(output, &bv)
                    .map_err(VmError::memory)?;
                self.store
                    .mark_output_complete(output)
                    .map_err(VmError::memory)?;

                self.store.flush_decode().map_err(VmError::memory)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mpz_circuits_data::AES128;
    use mpz_common::context::test_st_context;
    use mpz_memory_core::{Array, MemoryExt, ViewExt, binary::U8};
    use mpz_vm_core::{Call, CallableExt, Execute};

    use crate::vm::IdealVm;

    #[tokio::test]
    async fn test_vm() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let mut party_a = IdealVm::new();
        let mut party_b = IdealVm::new();

        let (a_out, b_out) = futures::join!(
            async {
                let key: Array<U8, 16> = party_a.alloc().unwrap();
                let msg: Array<U8, 16> = party_a.alloc().unwrap();

                party_a.mark_private(key).unwrap();
                party_a.mark_blind(msg).unwrap();

                let ciphertext: Array<U8, 16> = party_a
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = party_a.decode(ciphertext).unwrap();

                party_a.assign(key, [0u8; 16]).unwrap();
                party_a.commit(key).unwrap();
                party_a.commit(msg).unwrap();

                party_a.execute_all(&mut ctx_a).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let key: Array<U8, 16> = party_b.alloc().unwrap();
                let msg: Array<U8, 16> = party_b.alloc().unwrap();

                party_b.mark_blind(key).unwrap();
                party_b.mark_private(msg).unwrap();

                let ciphertext: Array<U8, 16> = party_b
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = party_b.decode(ciphertext).unwrap();

                party_b.assign(msg, [42u8; 16]).unwrap();
                party_b.commit(key).unwrap();
                party_b.commit(msg).unwrap();

                party_b.execute_all(&mut ctx_b).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(a_out, b_out);
    }

    #[tokio::test]
    async fn test_vm_chained() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);

        let mut party_a = IdealVm::new();
        let mut party_b = IdealVm::new();

        let (a_out, b_out) = futures::join!(
            async {
                let key: Array<U8, 16> = party_a.alloc().unwrap();
                let msg: Array<U8, 16> = party_a.alloc().unwrap();
                let key2: Array<U8, 16> = party_a.alloc().unwrap();

                party_a.mark_private(key).unwrap();
                party_a.mark_blind(msg).unwrap();
                party_a.mark_public(key2).unwrap();

                let output: Array<U8, 16> = party_a
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = party_a
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key2)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = party_a.decode(ciphertext).unwrap();

                party_a.assign(key, [0u8; 16]).unwrap();
                party_a.commit(key).unwrap();
                party_a.commit(msg).unwrap();
                party_a.assign(key2, [1u8; 16]).unwrap();
                party_a.commit(key2).unwrap();

                party_a.execute_all(&mut ctx_a).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            },
            async {
                let key: Array<U8, 16> = party_b.alloc().unwrap();
                let msg: Array<U8, 16> = party_b.alloc().unwrap();
                let key2: Array<U8, 16> = party_b.alloc().unwrap();

                party_b.mark_blind(key).unwrap();
                party_b.mark_private(msg).unwrap();
                party_b.mark_public(key2).unwrap();

                let output: Array<U8, 16> = party_b
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key)
                            .arg(msg)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                // Chain the AES calls.
                let ciphertext: Array<U8, 16> = party_b
                    .call(
                        Call::builder(AES128.clone())
                            .arg(key2)
                            .arg(output)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();

                let mut ciphertext = party_b.decode(ciphertext).unwrap();

                party_b.assign(msg, [42u8; 16]).unwrap();
                party_b.commit(key).unwrap();
                party_b.commit(msg).unwrap();
                party_b.assign(key2, [1u8; 16]).unwrap();
                party_b.commit(key2).unwrap();

                party_b.execute_all(&mut ctx_b).await.unwrap();
                ciphertext.try_recv().unwrap().unwrap()
            }
        );

        assert_eq!(a_out, b_out);
    }
}
