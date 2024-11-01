//! ROLE sender.

use std::collections::VecDeque;

use hybrid_array::Array;
use rand::SeedableRng;

use mpz_common::future::{new_output, MaybeDone, Sender as OutputSender};
use mpz_core::{prg::Prg, Block};
use mpz_fields::Field;
use mpz_ot_core::rot::{ROTSender, ROTSenderOutput};

use crate::{OLEId, OLEShare, ROLESender, ROLESenderOutput, SenderMasks};

#[derive(Debug)]
struct Queued<F> {
    count: usize,
    sender: OutputSender<ROLESenderOutput<F>>,
}

/// ROLE Sender wrapping a random OT sender.
#[derive(Debug)]
pub struct Sender<T, F> {
    id: OLEId,
    alloc: usize,
    pending: usize,
    queue: VecDeque<Queued<F>>,
    rot: T,
    prg: Prg,
    role: Vec<OLEShare<F>>,
}

impl<T, F> Sender<T, F> {
    /// Creates a new ROLE sender.
    ///
    /// # Arguments
    ///
    /// * `seed` - Random seed for the sender.
    /// * `rot` - Random OT sender.
    pub fn new(seed: Block, rot: T) -> Self {
        Self {
            id: OLEId::default(),
            alloc: 0,
            pending: 0,
            queue: VecDeque::new(),
            rot,
            prg: Prg::from_seed(seed),
            role: Vec::new(),
        }
    }

    /// Returns the random OT sender.
    pub fn rot(&self) -> &T {
        &self.rot
    }

    /// Returns a mutable reference to the random OT sender.
    pub fn rot_mut(&mut self) -> &mut T {
        &mut self.rot
    }

    /// Returns the random OT sender.
    pub fn into_inner(self) -> T {
        self.rot
    }
}

impl<T, F> Sender<T, F>
where
    T: ROTSender<[F; 2]>,
    F: Field,
{
    /// Returns `true` if the sender wants to send.
    pub fn wants_send(&self) -> bool {
        self.alloc > 0
    }

    /// Evaluates the OLEs as the sender.
    pub fn send(&mut self) -> Result<SenderMasks<F>, SenderError> {
        let count = self.alloc;
        if self.pending > count {
            return Err(SenderError(ErrorRepr::InsufficientOle {
                count: self.pending,
                available: count,
            }));
        }

        let ROTSenderOutput { keys: masks, .. } = self
            .rot
            .try_send_rot(count * F::BIT_SIZE)
            .map_err(SenderError::ot)?;

        let (shares, masks): (Vec<_>, Vec<_>) = masks
            .chunks(F::BIT_SIZE)
            .map(|masks| {
                OLEShare::new_ole_sender(
                    F::rand(&mut self.prg),
                    Array::try_from(masks)
                        .expect("slice should have length of bit size of field element"),
                )
            })
            .unzip();

        let mut i = 0;
        for Queued { count, sender } in self.queue.drain(..) {
            let shares = shares[i..i + count].to_vec();
            i += count;

            sender.send(ROLESenderOutput {
                id: self.id.next(),
                shares,
            });
        }

        self.role.extend_from_slice(&shares[i..]);
        self.alloc = 0;
        self.pending = 0;

        Ok(SenderMasks { masks })
    }
}

impl<T, F> ROLESender<F> for Sender<T, F>
where
    T: ROTSender<[F; 2]>,
    F: Field,
{
    type Error = SenderError;
    type Future = MaybeDone<ROLESenderOutput<F>>;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        self.rot
            .alloc(count * F::BIT_SIZE)
            .map_err(SenderError::ot)?;

        self.alloc += count;

        Ok(())
    }

    fn available(&self) -> usize {
        self.role.len()
    }

    fn try_send_role(&mut self, count: usize) -> Result<ROLESenderOutput<F>, Self::Error> {
        if count > self.role.len() {
            return Err(SenderError(ErrorRepr::InsufficientOle {
                count,
                available: self.role.len(),
            }));
        }

        let shares = self.role.drain(..count).collect();

        Ok(ROLESenderOutput {
            id: self.id.next(),
            shares,
        })
    }

    fn queue_send_role(&mut self, count: usize) -> Result<Self::Future, Self::Error> {
        let (sender, recv) = new_output();

        self.pending += count;
        self.queue.push_back(Queued { count, sender });

        Ok(recv)
    }
}

/// Error for [`Sender`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SenderError(#[from] ErrorRepr);

impl SenderError {
    fn ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("ot error: {0}")]
    Ot(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("insufficient OLE, wanted: {count}, available: {available}")]
    InsufficientOle { count: usize, available: usize },
}
