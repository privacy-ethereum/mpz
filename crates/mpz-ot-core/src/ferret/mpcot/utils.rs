/// Pads `n` to next power of two and returns (log2, length)
pub fn padded_log2_and_length(n: usize) -> (usize, usize) {
    let pow2 = (n + 1).checked_next_power_of_two().unwrap();
    (pow2.ilog2() as usize, pow2)
}