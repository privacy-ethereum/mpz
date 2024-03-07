// This example demonstrates how to securely and privately transfer data using OT.
// In practical situations data would be communicated over a channel such as TCP.
// For simplicity, this example shows how to use CO15 OT in memory.

use mpz_core::Block;
use mpz_ot_core::chou_orlandi::{Receiver, Sender};

pub fn main() {
    // Receiver choice bits
    let choices = vec![false, true, false, false, true, true, false, true];

    println!("Receiver choices: {:?}", &choices);

    // Sender messages the receiver chooses from
    let inputs = [[Block::ZERO, Block::ONES]; 8];

    println!("Sender inputs: {:?}", &inputs);

    // First the sender creates a setup message and passes it to receiver
    let (sender_setup, mut sender) = Sender::default().setup();

    // Receiver takes sender's setup and generates the receiver payload
    let mut receiver = Receiver::default().setup(sender_setup);
    let receiver_payload = receiver.receive_random(&choices);

    // Finally, sender encrypts their inputs and sends them to receiver
    let sender_payload = sender.send(&inputs, receiver_payload).unwrap();

    // Receiver takes the encrypted inputs and is able to decrypt according to their choice bits
    let received = receiver.receive(sender_payload).unwrap();

    println!("Transferred messages: {:?}", received);
}
