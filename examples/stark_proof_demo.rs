use zkp_rs::{
    backend::stark_prover::StarkProver,
    config::CircuitConfig,
    core::{Prove, types::{Commitment, Claim, Statement, Witness}},
};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 STARK Prover Integration Demo");
    println!("================================");

    // Create circuit configuration
    let config = CircuitConfig {
        max_text_len: 64,
        max_substring_len: 32,
        enable_multi_block_sha: false,
    };

    // Initialize STARK prover
    let prover = StarkProver::new(config);
    println!("✅ StarkProver initialized");

    // Test case 1: Valid substring proof
    println!("\n📝 Test 1: Valid substring proof");
    test_valid_proof(&prover)?;

    // Test case 2: Invalid substring proof
    println!("\n📝 Test 2: Invalid substring proof");
    test_invalid_proof(&prover)?;

    // Test case 3: Complex substring proof
    println!("\n📝 Test 3: Complex substring proof");
    test_complex_proof(&prover)?;

    println!("\n🎉 All tests completed successfully!");
    Ok(())
}

fn test_valid_proof(prover: &StarkProver) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"The quick brown fox jumps over the lazy dog".to_vec();
    let substring = "quick brown fox".to_string();

    // Create commitment (SHA-256 hash of plaintext)
    let hash = Sha256::digest(&plaintext);
    let commitment = Commitment { inner: hash.to_vec() };

    // Create statement and witness
    let statement = Statement {
        commitment,
        claim: Claim::Substring { value: substring.clone() },
    };
    let witness = Witness { plaintext: plaintext.clone() };

    println!("  Plaintext: {}", String::from_utf8_lossy(&plaintext));
    println!("  Substring: {}", substring);
    println!("  Commitment: {}", hex::encode(&statement.commitment.inner));

    // Generate proof
    println!("  🔄 Generating STARK proof...");
    let proof = prover.prove(&statement, &witness);
    println!("  ✅ Proof generated ({} bytes)", proof.inner.len());

    // Verify proof
    println!("  🔄 Verifying proof...");
    let is_valid = prover.verify(&statement, &proof);
    
    if is_valid {
        println!("  ✅ Proof verification PASSED");
    } else {
        println!("  ❌ Proof verification FAILED");
        return Err("Valid proof failed verification".into());
    }

    Ok(())
}

fn test_invalid_proof(prover: &StarkProver) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"Hello world!".to_vec();
    let substring = "goodbye".to_string(); // This substring is NOT in the plaintext

    // Create commitment
    let hash = Sha256::digest(&plaintext);
    let commitment = Commitment { inner: hash.to_vec() };

    // Create statement and witness
    let statement = Statement {
        commitment,
        claim: Claim::Substring { value: substring.clone() },
    };
    let witness = Witness { plaintext: plaintext.clone() };

    println!("  Plaintext: {}", String::from_utf8_lossy(&plaintext));
    println!("  Substring: {} (NOT in plaintext)", substring);

    // Generate proof
    println!("  🔄 Generating proof for invalid case...");
    let proof = prover.prove(&statement, &witness);
    println!("  ✅ Proof generated ({} bytes)", proof.inner.len());

    // Verify proof - should fail
    println!("  🔄 Verifying proof...");
    let is_valid = prover.verify(&statement, &proof);
    
    if !is_valid {
        println!("  ✅ Proof verification correctly FAILED");
    } else {
        println!("  ❌ Proof verification should have FAILED but PASSED");
        return Err("Invalid proof incorrectly passed verification".into());
    }

    Ok(())
}

fn test_complex_proof(prover: &StarkProver) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit".to_vec();
    let substring = "consectetur".to_string();

    // Create commitment
    let hash = Sha256::digest(&plaintext);
    let commitment = Commitment { inner: hash.to_vec() };

    // Create statement and witness
    let statement = Statement {
        commitment,
        claim: Claim::Substring { value: substring.clone() },
    };
    let witness = Witness { plaintext: plaintext.clone() };

    println!("  Plaintext: {}", String::from_utf8_lossy(&plaintext));
    println!("  Substring: {}", substring);

    // Generate and verify proof
    println!("  🔄 Generating proof...");
    let proof = prover.prove(&statement, &witness);
    println!("  ✅ Proof generated ({} bytes)", proof.inner.len());

    println!("  🔄 Verifying proof...");
    let is_valid = prover.verify(&statement, &proof);
    
    if is_valid {
        println!("  ✅ Complex proof verification PASSED");
    } else {
        println!("  ❌ Complex proof verification FAILED");
        return Err("Complex proof failed verification".into());
    }

    // Test with different statement (should fail)
    let different_substring = "different".to_string();
    let different_statement = Statement {
        commitment: statement.commitment.clone(),
        claim: Claim::Substring { value: different_substring },
    };

    println!("  🔄 Testing proof with different statement...");
    let is_valid_different = prover.verify(&different_statement, &proof);
    
    if !is_valid_different {
        println!("  ✅ Proof correctly FAILED with different statement");
    } else {
        println!("  ❌ Proof should have FAILED with different statement");
        return Err("Proof incorrectly passed with different statement".into());
    }

    Ok(())
}