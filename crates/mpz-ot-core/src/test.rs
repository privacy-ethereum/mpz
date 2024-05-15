//! OT test utilities.

use mpz_core::Block;

/// Asserts the correctness of correlated oblivious transfer.
pub fn assert_cot(delta: Block, choices: &[bool], msgs: &[Block], received: &[Block]) {
    assert!(choices.into_iter().zip(msgs.into_iter().zip(received)).all(
        |(&choice, (&msg, &received))| {
            if choice {
                received == msg ^ delta
            } else {
                received == msg
            }
        }
    ));
}

/// Asserts the correctness of random oblivious transfer.
pub fn assert_rot<T: Copy + PartialEq>(choices: &[bool], msgs: &[[T; 2]], received: &[T]) {
    assert!(choices.into_iter().zip(msgs.into_iter().zip(received)).all(
        |(&choice, (&msg, &received))| {
            if choice {
                received == msg[1]
            } else {
                received == msg[0]
            }
        }
    ));
}
