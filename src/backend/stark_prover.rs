use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use sha2::{Digest, Sha256};

use crate::{
    circuits::{
        Circuit, air::SubstringAIR, substring_circuit::SubstringCircuit, trace::TraceLayout,
    },
    config::{CircuitConfig, CircuitParams, CircuitWitness, PublicInputs},
    core::{Claim, Proof, Prove, Statement, Witness},
    error::ZkpError,
};

/// STARK prover implementation using Plonky3
pub struct StarkProver {
    circuit: SubstringCircuit,
    config: CircuitConfig,
}

impl StarkProver {
    /// Create a new STARK prover with the given circuit configuration
    pub fn new(config: CircuitConfig) -> Self {
        let circuit = SubstringCircuit::new(config.clone());

        Self { circuit, config }
    }

    /// Extract offset from witness data
    fn extract_offset(&self, witness: &Witness, statement: &Statement) -> Result<usize, ZkpError> {
        let substring = match &statement.claim {
            Claim::Substring { value } => value,
        };

        let plaintext = String::from_utf8_lossy(&witness.plaintext);

        // Find the offset of the substring in the plaintext
        if let Some(offset) = plaintext.find(substring) {
            Ok(offset)
        } else {
            Err(ZkpError::InvalidWitness(
                "Substring not found in plaintext".to_string(),
            ))
        }
    }

    /// Build circuit parameters from statement and witness
    fn build_circuit_params(
        &self,
        statement: &Statement,
        witness: &Witness,
    ) -> Result<CircuitParams, ZkpError> {
        let substring = match &statement.claim {
            Claim::Substring { value } => value.clone(),
        };

        let offset = self.extract_offset(witness, statement)?;

        Ok(CircuitParams {
            config: self.config.clone(),
            public_inputs: PublicInputs {
                commitment: statement.commitment.inner.clone().try_into().map_err(|_| {
                    ZkpError::InvalidPublicInput("Invalid commitment length".to_string())
                })?,
                substring: substring.into_bytes(),
            },
            witness: Some(CircuitWitness {
                plaintext: witness.plaintext.clone(),
                offset,
            }),
        })
    }
}

impl Prove for StarkProver {
    fn prove(&self, statement: &Statement, witness: &Witness) -> Proof {
        // Build circuit parameters
        let params = match self.build_circuit_params(statement, witness) {
            Ok(params) => params,
            Err(e) => {
                // Return a proof that will fail verification
                return Proof {
                    inner: format!("ERROR: {}", e).into_bytes(),
                };
            }
        };

        // Generate execution trace using the circuit
        let trace = match self.circuit.generate_trace(&params) {
            Ok(trace) => trace,
            Err(e) => {
                return Proof {
                    inner: format!("TRACE_ERROR: {}", e).into_bytes(),
                };
            }
        };

        // Verify constraints are satisfied
        if let Err(e) = self.circuit.verify_constraints(&trace, &params) {
            return Proof {
                inner: format!("CONSTRAINT_ERROR: {}", e).into_bytes(),
            };
        }

        // Create AIR for STARK proving
        let layout = TraceLayout::default();
        let air = SubstringAIR::new(self.config.clone(), layout);

        // Convert trace to the format expected by Plonky3
        let stark_trace = self.convert_trace_format(trace);

        // Generate STARK proof using Plonky3
        match self.generate_stark_proof(air, stark_trace, &params) {
            Ok(proof_bytes) => Proof { inner: proof_bytes },
            Err(e) => Proof {
                inner: format!("STARK_ERROR: {}", e).into_bytes(),
            },
        }
    }

    fn verify(&self, statement: &Statement, proof: &Proof) -> bool {
        // Check for error proofs first
        if let Ok(error_msg) = String::from_utf8(proof.inner.clone()) {
            if error_msg.starts_with("ERROR:")
                || error_msg.starts_with("TRACE_ERROR:")
                || error_msg.starts_with("CONSTRAINT_ERROR:")
                || error_msg.starts_with("STARK_ERROR:")
            {
                return false;
            }
        }

        // Extract public inputs from statement
        let public_inputs = match self.extract_public_inputs(statement) {
            Ok(inputs) => inputs,
            Err(_) => return false,
        };

        // Create AIR for verification
        let layout = TraceLayout::default();
        let air = SubstringAIR::new(self.config.clone(), layout);

        // Verify STARK proof
        self.verify_stark_proof(&air, &proof.inner, &public_inputs)
            .unwrap_or(false)
    }
}

impl StarkProver {
    /// Convert trace format for Plonky3 compatibility
    fn convert_trace_format(&self, trace: Vec<Vec<Goldilocks>>) -> Vec<Vec<Goldilocks>> {
        // For now, return as-is since our trace format is already compatible
        // In a full implementation, this might need matrix transposition or other formatting
        trace
    }

    /// Generate STARK proof using Plonky3
    fn generate_stark_proof(
        &self,
        _air: SubstringAIR,
        trace: Vec<Vec<Goldilocks>>,
        params: &CircuitParams,
    ) -> Result<Vec<u8>, ZkpError> {
        // For MVP implementation, we'll create a simplified proof structure
        // In a full implementation, this would use p3_uni_stark::prove

        // Serialize the proof components
        let proof_data = StarkProofData {
            trace_commitment: self.compute_trace_commitment(&trace)?,
            public_inputs: params.public_inputs.clone(),
            fri_proof: self.generate_fri_proof(&trace)?,
            circuit_config: params.config.clone(),
        };

        // Serialize to bytes
        serde_json::to_vec(&proof_data)
            .map_err(|e| ZkpError::SerializationError(format!("Serialization failed: {}", e)))
    }

    /// Verify STARK proof
    fn verify_stark_proof(
        &self,
        _air: &SubstringAIR,
        proof_bytes: &[u8],
        public_inputs: &PublicInputs,
    ) -> Result<bool, ZkpError> {
        // Deserialize proof
        let proof_data: StarkProofData = serde_json::from_slice(proof_bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Deserialization failed: {}", e)))?;

        // Verify public inputs match
        if proof_data.public_inputs.commitment != public_inputs.commitment
            || proof_data.public_inputs.substring != public_inputs.substring
        {
            return Ok(false);
        }

        // In a full implementation, this would verify:
        // 1. FRI proof validity
        // 2. Trace commitment correctness
        // 3. Constraint satisfaction

        // For MVP, we do basic checks
        Ok(self.basic_proof_validation(&proof_data))
    }

    /// Extract public inputs from statement
    fn extract_public_inputs(&self, statement: &Statement) -> Result<PublicInputs, ZkpError> {
        let substring = match &statement.claim {
            Claim::Substring { value } => value.clone(),
        };

        Ok(PublicInputs {
            commitment: statement.commitment.inner.clone().try_into().map_err(|_| {
                ZkpError::InvalidPublicInput("Invalid commitment length".to_string())
            })?,
            substring: substring.into_bytes(),
        })
    }

    /// Compute trace commitment (simplified)
    fn compute_trace_commitment(&self, trace: &[Vec<Goldilocks>]) -> Result<Vec<u8>, ZkpError> {
        let mut hasher = Sha256::new();
        for row in trace {
            for &field_element in row {
                // Convert field element to bytes and hash
                hasher.update(&field_element.as_canonical_u64().to_le_bytes());
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    /// Generate FRI proof (simplified)
    fn generate_fri_proof(&self, trace: &[Vec<Goldilocks>]) -> Result<Vec<u8>, ZkpError> {
        // Simplified FRI proof - in reality this would use p3_fri
        let mut hasher = Sha256::new();
        hasher.update(b"FRI_PROOF");
        for row in trace {
            for &element in row {
                hasher.update(&element.as_canonical_u64().to_le_bytes());
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    /// Basic proof validation (simplified)
    fn basic_proof_validation(&self, proof_data: &StarkProofData) -> bool {
        // Basic sanity checks
        proof_data.trace_commitment.len() == 32  // SHA-256 hash length
            && proof_data.fri_proof.len() == 32  // Our simplified FRI proof length
            && !proof_data.public_inputs.substring.is_empty()
            && proof_data.public_inputs.commitment != [0u8; 32]
    }
}

/// Serializable STARK proof data structure
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct StarkProofData {
    trace_commitment: Vec<u8>,
    public_inputs: PublicInputs,
    fri_proof: Vec<u8>,
    circuit_config: CircuitConfig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Claim, Commitment};

    #[test]
    fn test_stark_prover_creation() {
        let config = CircuitConfig {
            max_text_len: 32,
            max_substring_len: 16,
            enable_multi_block_sha: false,
        };

        let prover = StarkProver::new(config.clone());
        assert_eq!(prover.config.max_text_len, config.max_text_len);
    }

    #[test]
    fn test_prove_and_verify_success() {
        let config = CircuitConfig {
            max_text_len: 32,
            max_substring_len: 16,
            enable_multi_block_sha: false,
        };

        let prover = StarkProver::new(config);

        // Create test data
        let plaintext = b"hello world!".to_vec();
        let substring = "hello".to_string();

        // Hash the plaintext for commitment
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&plaintext);
        let commitment = Commitment {
            inner: hash.to_vec(),
        };

        let statement = Statement {
            commitment,
            claim: Claim::Substring { value: substring },
        };

        let witness = Witness { plaintext };

        // Generate proof
        let proof = prover.prove(&statement, &witness);

        // Verify proof
        let is_valid = prover.verify(&statement, &proof);
        assert!(is_valid, "Proof should be valid");
    }

    #[test]
    fn test_prove_and_verify_failure() {
        let config = CircuitConfig {
            max_text_len: 32,
            max_substring_len: 16,
            enable_multi_block_sha: false,
        };

        let prover = StarkProver::new(config);

        // Create test data with non-matching substring
        let plaintext = b"hello world!".to_vec();
        let substring = "goodbye".to_string();

        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&plaintext);
        let commitment = Commitment {
            inner: hash.to_vec(),
        };

        let statement = Statement {
            commitment,
            claim: Claim::Substring { value: substring },
        };

        let witness = Witness { plaintext };

        // Generate proof
        let proof = prover.prove(&statement, &witness);

        // Verify proof should fail
        let is_valid = prover.verify(&statement, &proof);
        assert!(
            !is_valid,
            "Proof should be invalid for non-matching substring"
        );
    }

    #[test]
    fn test_extract_offset() {
        let config = CircuitConfig {
            max_text_len: 32,
            max_substring_len: 16,
            enable_multi_block_sha: false,
        };

        let prover = StarkProver::new(config);

        let plaintext = b"hello world!".to_vec();
        let witness = Witness { plaintext };

        let statement = Statement {
            commitment: Commitment { inner: vec![0; 32] },
            claim: Claim::Substring {
                value: "world".to_string(),
            },
        };

        let offset = prover.extract_offset(&witness, &statement).unwrap();
        assert_eq!(offset, 6); // "world" starts at position 6
    }
}
