//! Implementation of Cuckoo hash.

use std::sync::Arc;

use mpz_core::{aes::AesEncryptor, Block};

use super::{CUCKOO_HASH_NUM, CUCKOO_TRIAL_NUM};

/// Cuckoo hash insertion error
#[derive(Debug, thiserror::Error)]
#[error("insertion loops")]
pub struct CuckooHashError;

/// Errors that can occur when handling Buckets.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum BucketError {
    #[error("invalid bucket state: expected {0}")]
    NotInBucket(String),
    #[error("invalid bucket index: expected {0}")]
    OutOfRange(String),
}

/// Item in Cuckoo hash table.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Item {
    /// Value in the table.
    pub(crate) value: u32,
    /// The hash index during the insertion.
    pub(crate) hash_index: usize,
}

/// Implementation of Cuckoo hash. See [here](https://eprint.iacr.org/2019/1084.pdf) for reference.
pub struct CuckooHash {
    hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
}

impl CuckooHash {
    /// Creates a new instance.
    #[inline]
    pub fn new(hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>) -> Self {
        Self { hashes }
    }

    /// Insert elements into a Cuckoo hash table.
    ///
    /// * Argument
    ///
    /// * `alphas` - A u32 vector being inserted.
    #[inline]
    pub fn insert(&self, alphas: &[u32]) -> Result<Vec<Option<Item>>, CuckooHashError> {
        // Always sets m = 1.5 * t. t is the length of `alphas`.
        let m = compute_table_length(alphas.len() as u32);

        // Allocates table.
        let mut table = vec![None; m];
        // Inserts each alpha.
        for &value in alphas {
            self.hash(&mut table, value)?
        }
        Ok(table)
    }

    // Hash an element to a position with the current hash function.
    #[inline]
    fn hash(&self, table: &mut [Option<Item>], value: u32) -> Result<(), CuckooHashError> {
        // The item consists of the value and hash index, starting from 0.
        let mut item = Item {
            value,
            hash_index: 0,
        };

        for _ in 0..CUCKOO_TRIAL_NUM {
            // Computes the position of the value.
            let pos = hash_to_index(&self.hashes[item.hash_index], table.len(), item.value);

            // Inserts the value to position `pos`.
            let opt_item = table[pos].replace(item);

            // If position `pos` is not empty before the above insertion, iteratively inserts the obtained value.
            if let Some(x) = opt_item {
                item = x;
                item.hash_index = (item.hash_index + 1) % CUCKOO_HASH_NUM;
            } else {
                // If no value assigned to position `pos`, end the process.
                return Ok(());
            }
        }
        Err(CuckooHashError)
    }
}

/// Implementation of Bucket. See step 3 in Figure 7
pub struct Bucket {
    // The hash functions.
    hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>,
    // The number of buckets.
    m: usize,
}

impl Bucket {
    /// Creates a new instance.
    #[inline]
    pub fn new(hashes: Arc<[AesEncryptor; CUCKOO_HASH_NUM]>, m: usize) -> Self {
        Self { hashes, m }
    }

    /// Inserts the input vector [0..n-1] into buckets.
    ///
    /// # Argument
    ///
    /// * `n` - The length of the vector [0..n-1].
    #[inline]
    pub fn insert(&self, n: u32) -> Vec<Vec<Item>> {
        let mut buckets = vec![Vec::default(); self.m];
        // NOTE: the sorted step in Step 3.c can be removed.
        for i in 0..n {
            for (index, hash) in self.hashes.iter().enumerate() {
                let pos = hash_to_index(hash, self.m, i);
                buckets[pos].push(Item {
                    value: i,
                    hash_index: index,
                });
            }
        }
        buckets
    }
}

// Always sets m = 1.5 * t. t is the length of `alphas`. See Section 7.1 Parameter Selection.
#[inline(always)]
pub(crate) fn compute_table_length(t: u32) -> usize {
    (1.5 * (t as f32)).ceil() as usize
}

// Hash the value into index using AES.
#[inline(always)]
pub(crate) fn hash_to_index(hash: &AesEncryptor, range: usize, value: u32) -> usize {
    let mut blk: Block = bytemuck::cast::<_, Block>(value as u128);
    blk = hash.encrypt_block(blk);
    let res = u128::from_le_bytes(blk.to_bytes());
    (res as usize) % range
}

// Finds the position of the item in each Bucket.
#[inline(always)]
pub(crate) fn find_pos(bucket: &[Item], item: &Item) -> Result<usize, BucketError> {
    let pos = bucket.iter().position(|&x| *item == x);
    pos.ok_or(BucketError::NotInBucket("not in the bucket".to_string()))
}

#[cfg(test)]
mod tests {
    use crate::ferret::cuckoo::find_pos;
    use std::sync::Arc;

    use super::{Bucket, CuckooHash};
    use mpz_core::{aes::AesEncryptor, prg::Prg};

    #[test]
    fn cockoo_hash_bucket_test() {
        let mut prg = Prg::new();
        const NUM: usize = 50;
        let hashes = Arc::new(std::array::from_fn(|_| {
            AesEncryptor::new(prg.random_block())
        }));
        let cuckoo = CuckooHash::new(hashes.clone());
        let input: [u32; NUM] = std::array::from_fn(|i| i as u32);

        let table = cuckoo.insert(&input).unwrap();

        let bucket = Bucket::new(hashes, table.len());
        let buckets = bucket.insert((2 * NUM) as u32);

        assert!(table
            .iter()
            .zip(buckets.iter())
            .all(|(value, bin)| match value {
                Some(x) => bin.contains(x),
                None => true,
            }));

        let _: Vec<usize> = table
            .iter()
            .zip(buckets.iter())
            .map(|(value, bin)| {
                if let Some(x) = value {
                    find_pos(bin, x).unwrap()
                } else {
                    bin.len() + 1
                }
            })
            .collect();
    }
}
