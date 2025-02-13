//! OT test utilities.

use mpz_core::Block;

/// Asserts the correctness of oblivious transfer.
pub fn assert_ot(choices: &[bool], msgs: &[[Block; 2]], received: &[Block]) {
    assert!(choices
        .iter()
        .zip(msgs.iter().zip(received))
        .all(|(&choice, (&msg, &received))| {
            if choice {
                received == msg[1]
            } else {
                received == msg[0]
            }
        }));
}

/// Asserts the correctness of correlated oblivious transfer.
pub fn assert_cot(delta: Block, choices: &[bool], keys: &[Block], macs: &[Block]) {
    assert!(choices
        .iter()
        .zip(keys.iter().zip(macs))
        .all(|(&choice, (&key, &mac))| {
            if choice {
                mac == key ^ delta
            } else {
                mac == key
            }
        }));
}

/// Asserts the correctness of random oblivious transfer.
pub fn assert_rot<T: Copy + PartialEq>(choices: &[bool], msgs: &[[T; 2]], received: &[T]) {
    assert!(choices
        .iter()
        .zip(msgs.iter().zip(received))
        .all(|(&choice, (&msg, &received))| {
            if choice {
                received == msg[1]
            } else {
                received == msg[0]
            }
        }));
}

/// Asserts the correctness of single-point correlated oblivious transfer.
pub fn assert_spcot(delta: Block, keys: &[Block], idx: usize, received: &[Block]) {
    assert_eq!(received.len(), keys.len());

    assert_eq!(
        keys.iter().fold(delta, |x_acc, x| x_acc ^ x),
        received.iter().fold(Block::ZERO, |x_acc, x| x_acc ^ x)
    );
    assert_eq!(keys[idx] ^ delta, received[idx]);
}
