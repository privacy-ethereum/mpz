//! General OT message types

use serde::{Deserialize, Serialize};

/// A message sent by the receiver which a sender can use to perform
/// Beaver derandomization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "UncheckedDerandomize")]
pub struct Derandomize {
    /// Transfer ID
    pub id: u32,
    /// The number of choices to derandomize.
    pub count: u32,
    /// Correction bits
    pub flip: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct UncheckedDerandomize {
    id: u32,
    count: u32,
    flip: Vec<u8>,
}

impl TryFrom<UncheckedDerandomize> for Derandomize {
    type Error = std::io::Error;

    fn try_from(value: UncheckedDerandomize) -> Result<Self, Self::Error> {
        // Divide by 8, rounding up
        let expected_len = (value.count as usize + 7) / 8;

        if value.flip.len() != expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "flip length does not match count",
            ));
        }

        Ok(Derandomize {
            id: value.id,
            count: value.count,
            flip: value.flip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchecked_derandomize() {
        assert!(Derandomize::try_from(UncheckedDerandomize {
            id: 0,
            count: 0,
            flip: vec![],
        })
        .is_ok());

        assert!(Derandomize::try_from(UncheckedDerandomize {
            id: 0,
            count: 9,
            flip: vec![0],
        })
        .is_err());
    }
}
