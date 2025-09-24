use crate::{
    core::{Commit, Commitment},
    hash::sha256::hash,
};

pub struct Sha256Commit;

impl Commit for Sha256Commit {
    fn commit(&self, input: &[u8]) -> Commitment {
        let hash = hash(input);
        Commitment {
            inner: hash.to_vec(),
        }
    }
}
