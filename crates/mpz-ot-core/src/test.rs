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
pub fn assert_cot(delta: Block, choices: &[bool], msgs: &[Block], received: &[Block]) {
    assert!(choices
        .iter()
        .zip(msgs.iter().zip(received))
        .all(|(&choice, (&msg, &received))| {
            if choice {
                received == msg ^ delta
            } else {
                received == msg
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
