use zkp_rs::{
    backend::{mock::MockProver, sha256_commit::Sha256Commit},
    core::{Claim, Commit, Prove, Statement, Witness},
};

fn main() {
    let statement = Statement {
        commitment: Sha256Commit.commit("血小板 50, 年龄 42".as_bytes()),
        claim: Claim::Substring {
            value: "年龄 42".into(),
        },
    };

    let witness = Witness {
        plaintext: "血小板 50, 年龄 42".as_bytes().to_vec(),
    };

    let prover = MockProver;
    let proof = prover.prove(&statement, &witness);
    assert!(prover.verify(&statement, &proof));
}
// 运行：cargo run --example mock_demo
