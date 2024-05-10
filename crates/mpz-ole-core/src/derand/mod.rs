//! Batched OLE implementation based on derandomization/adjustment of preprocessed OLEs.
//!
//! C.f. <https://crypto.stackexchange.com/questions/100634/converting-a-random-ole-oblivious-linear-function-evaluation-to-an-ole>.
//!
//! Base OLE is Sender: (ak_dash, xk_dash), Receiver (bk_dash, yk_dash).
//! Resulting OLE is Sender: (ak, xk), Receiver (bk, yk).

mod receiver;
mod sender;

pub use receiver::OLEReceiver;
pub use sender::OLESender;

#[cfg(test)]
mod tests {
    use super::{OLEReceiver, OLESender};
    use crate::ideal::OLEFunctionality;
    use mpz_core::{prg::Prg, Block};
    use mpz_fields::{p256::P256, UniformRand};
    use rand::SeedableRng;

    #[test]
    fn test_ole_derand() {
        let count = 12;
        let mut rng = Prg::from_seed(Block::ZERO);
        let mut ole: OLEFunctionality<P256> = OLEFunctionality::default();

        let sender: OLESender<P256> = OLESender::default();
        let receiver: OLEReceiver<P256> = OLEReceiver::default();

        let ak_dash: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk_dash: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        ole.sender_input(ak_dash.clone());
        ole.receiver_input(bk_dash.clone());

        let xk_dash = ole.send();
        let yk_dash = ole.receive();

        let ak: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();
        let bk: Vec<P256> = (0..count).map(|_| P256::rand(&mut rng)).collect();

        let uk = sender.create_mask(&ak_dash, &ak).unwrap();
        let vk = receiver.create_mask(&bk_dash, &bk).unwrap();

        let xk = sender.generate_output(&ak_dash, &xk_dash, &vk).unwrap();
        let yk = receiver.generate_output(&bk, &yk_dash, &uk).unwrap();

        yk.iter()
            .zip(xk.iter())
            .zip(ak.iter())
            .zip(bk.iter())
            .for_each(|(((&y, &x), &a), &b)| assert_eq!(y, a * b + x));
    }
}
