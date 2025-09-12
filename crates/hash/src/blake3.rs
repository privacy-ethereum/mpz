//! Blake3 hash function.

use blake3::{BLOCK_LEN, CHUNK_LEN};
use mpz_circuits::circuits::BLAKE3_COMPRESS;
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{memory::{binary::{Binary, U32, U8}, Array, MemoryExt, Slice, ToRaw, Vector, ViewExt}, Call, CallableExt, Vm, VmError};

/// The default initialization vector.
/// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L35-L37.
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
// Flag values.
// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L27C1-L28C31.
const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
/// Block size in bits.
const BLOCK_SIZE: usize = BLOCK_LEN * 8; // 512
/// Chunk size in bits.
const CHUNK_SIZE: usize = CHUNK_LEN * 8; // 8192

struct Block {
    data: Vec<Slice>,
    len: usize,
}

enum Visibility {
    Private,
    Public
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L166.
struct ChainingValue(Array<U32, 8>);
    
impl ChainingValue {
    fn new(vm: &mut dyn Vm<Binary>, visibility: Visibility, value: [u32; 8]) -> Result<Self, Blake3Error> {
        let state = vm.alloc()?;

        match visibility {
            // When keyed hash mode is used, chaining value is initialised with the private key.
            Visibility::Private => vm.mark_private(state)?,
            // When normal hash mode is used, , chaining value is initialised with the public IV.
            // We need to use this mode as ZK circuit DSL (Noir, Circom) only support this for now.
            Visibility::Public => vm.mark_public(state)?,
        };

        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }

    // Updated after compression of each block — needs to be private.
    fn update(&mut self, state: Array<U32, 8>) {
        self.0 = state
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L87-L88.
// TODO: Check if this state can be public.
struct State(Array<U32, 7>);

impl State {
    fn new(
        vm: &mut dyn Vm<Binary>,
        chunk_counter: u64,
        block_len: u32,
    ) -> Result<Self, Blake3Error> {
        let counter_low = chunk_counter as u32;
        let counter_high = (chunk_counter >> 32) as u32;
        #[rustfmt::skip]
        let value = [
            IV[0],             IV[1],             IV[2],             IV[3],
            counter_low,       counter_high,      block_len,
        ];
        let state= vm.alloc()?;
        vm.mark_public(state)?;
        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }
}

// Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L87-L88.
// Separated this from `State` because `State` only needs to be initialised once per chunk, whereas this
// changes for every block. 
struct Flags(U32);

impl Flags {
    fn new (vm: &mut dyn Vm<Binary>, value: u32) -> Result<Self, Blake3Error> {
        let state = vm.alloc()?;
        vm.mark_public(state)?;
        vm.assign(state, value)?;
        vm.commit(state)?;

        Ok(Self(state))
    }
}

struct ChunkState {
    blocks: Vec<Block>,
    chaining_value: ChainingValue,
    state: State,
    flags: u32,
}

impl ChunkState {
    fn new(
        vm: &mut dyn Vm<Binary>,
        chaining_value: ChainingValue,
        chunk_counter: u64,
        flags: u32
    ) -> Result<Self, Blake3Error> {
        Ok(Self {
            chaining_value,
            blocks: Vec::new(),
            state: State::new(vm, chunk_counter, BLOCK_LEN as u32)?,
            flags,
        })
    }

    /// Updates the hash with the provided data.
    fn update_slice(&mut self, mut data: Slice) {
        if data.len() == 0 {
            return;
        }

        // If the last block is not full, add the data to it.
        if let Some(block) = self.blocks.last_mut()
            && block.len < BLOCK_SIZE
        {
            let diff = BLOCK_SIZE - block.len;
            let (left, right) = data.split_at(diff.min(data.len()));
            block.data.push(left);
            block.len += left.len();
            data = right;
        }

        // Partition the rest of the data into blocks.
        while data.len() > 0 {
            let (left, right) = data.split_at(BLOCK_SIZE.min(data.len()));
            self.blocks.push(Block {
                data: vec![left],
                len: left.len(),
            });
            data = right;
        }
    }

    /// Updates the hash with the provided data.
    /// TODO: convert data to little endian word (32 bit), ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L117.
    fn update(&mut self, data: &Vector<U8>) {
        self.update_slice(data.to_raw());
    }

    /// Compresses the data in the internal buffer.
    /// This should only be called after all data has been `updated`.
    fn compress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), Blake3Error> {
        let no_of_blocks = self.blocks.len();
        debug_assert!(no_of_blocks >= 1, "there should be at least one block");

        // Ensure that the last block is full.
        if self.blocks.last().unwrap().len != BLOCK_SIZE {
            let padding_len = BLOCK_SIZE - self.blocks.last().unwrap().len;
            let padding = vm.alloc_raw(padding_len)?;
            vm.mark_public_raw(padding)?;

            let padding_data = BitVec::repeat(false, padding_len);
            vm.assign_raw(padding, padding_data)?;
            vm.commit_raw(padding)?;

            self.update_slice(padding);
        }

        for (i, block) in self.blocks.drain(..).enumerate() {
            let mut flags = self.flags;
            // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L210.
            if i == 0 {
                flags |= CHUNK_START;
            }
            // Ref: https://github.com/BLAKE3-team/BLAKE3/blob/3a90f0f06a429e6ce1d337b28156a75d2a372d7b/reference_impl/reference_impl.rs#L234.
            if i == no_of_blocks - 1 {
                flags |= CHUNK_END;
            }

            let flags = Flags::new(vm, flags)?;

            let mut builder = Call::builder(BLAKE3_COMPRESS.clone());
            for slice in block.data {
                builder = builder.arg(slice);
            }

            builder = builder.arg(self.chaining_value.0);
            builder = builder.arg(self.state.0);

            let call = builder
                .arg(flags.0)
                .build()
                .expect("compress circuit should have 1024 bit input");

            let output: Array<U32, 16>= vm.call(call)?;
            let truncated: Array<U32, 8> = output.get(0).expect("should be able to truncate output to 256 bits");
            self.chaining_value.update(truncated);
        }

        debug_assert!(
            self.blocks.len() == 0,
            "there should be no block left"
        );

        Ok(())
    }
}

/// Error for [`Blake3`].
#[derive(Debug, thiserror::Error)]
#[error("blake3 error: {0}")]
pub struct Blake3Error(#[from] VmError);
