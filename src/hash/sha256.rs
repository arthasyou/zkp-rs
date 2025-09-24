use sha2::{Digest, Sha256};

pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

pub fn verify(data: &[u8], expected_hash: &[u8; 32]) -> bool {
    hash(data) == *expected_hash
}
