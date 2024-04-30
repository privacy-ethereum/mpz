use mpz_core::Block;

/// Asserts the correctness of correlated oblivious transfer.
pub(crate) fn assert_cot(delta: Block, choices: &[bool], msgs: &[Block], received: &[Block]) {
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
