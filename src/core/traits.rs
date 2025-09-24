use crate::core::types::{Commitment, Proof, Statement, Witness};

pub trait Commit {
    fn commit(&self, input: &[u8]) -> Commitment;
}

pub trait Prove {
    fn prove(&self, statement: &Statement, witness: &Witness) -> Proof;
    fn verify(&self, statement: &Statement, proof: &Proof) -> bool;
}
