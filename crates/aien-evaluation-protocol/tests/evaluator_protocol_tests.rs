use aien_evaluation_protocol::{
    CanaryRollbackHarness, CryptographicTier, EvaluationError, EvaluationPlan, EvaluationReceipt,
    Evaluator, EvaluatorDescriptor, EvaluatorIdentity, EvaluatorOutcome, EvaluatorStatus, Finding,
    Measurement, SignedEvaluationReceipt, Verdict, VerifierIdentity,
};
use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::{SigningKey, VerifyingKey};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct MockEvaluator {
    id: String,
    status: EvaluatorStatus,
    findings: Vec<Finding>,
}

#[async_trait::async_trait]
impl Evaluator for MockEvaluator {
    fn descriptor(&self) -> EvaluatorDescriptor {
        EvaluatorDescriptor {
            evaluator_id: self.id.clone(),
            version: "1.0.0".to_string(),
            required: true,
        }
    }

    async fn evaluate(
        &self,
        _plan: &EvaluationPlan,
        _subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError> {
        Ok(EvaluatorOutcome {
            evaluator: EvaluatorIdentity {
                evaluator_id: self.id.clone(),
                version: "1.0.0".to_string(),
                binary_digest: Digest32([1u8; 32]),
                config_digest: Digest32([2u8; 32]),
            },
            status: self.status,
            findings: self.findings.clone(),
            measurements: vec![Measurement {
                metric: "unslop_score".to_string(),
                value: 1.0,
                unit: "ratio".to_string(),
            }],
            evidence: vec![],
            execution_digest: Digest32::ZERO,
        })
    }
}

fn create_sample_plan() -> EvaluationPlan {
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId::new_v4(),
        subject: ArtifactRef {
            artifact_id: uuid::Uuid::new_v4(),
            digest: Digest32([10u8; 32]),
            media_type: "application/rust".to_string(),
            byte_size: 4096,
        },
        profile: "strict-systems".to_string(),
        evaluators: vec![
            EvaluatorDescriptor {
                evaluator_id: "zeta-auditor".to_string(),
                version: "1.0.0".to_string(),
                required: true,
            },
            EvaluatorDescriptor {
                evaluator_id: "alpha-unslop".to_string(),
                version: "1.0.0".to_string(),
                required: true,
            },
        ],
        baseline: Some(ArtifactRef {
            artifact_id: uuid::Uuid::new_v4(),
            digest: Digest32([9u8; 32]),
            media_type: "application/rust".to_string(),
            byte_size: 4096,
        }),
        sandbox_profile: "bubblewrap-airgap".to_string(),
        policy_digest: Digest32([3u8; 32]),
        evaluator_manifest_digest: Digest32([4u8; 32]),
        plan_digest: Digest32::ZERO,
    };
    plan.plan_digest = plan.compute_plan_digest();
    plan
}

#[test]
fn test_evaluation_plan_deterministic_digest_and_verification() {
    let plan = create_sample_plan();
    assert!(plan.verify_plan_digest());

    // Shuffling evaluators order preserves digest due to internal sorting
    let mut plan_shuffled = plan.clone();
    plan_shuffled.evaluators.reverse();
    assert_eq!(plan.compute_plan_digest(), plan_shuffled.compute_plan_digest());

    // Tampering with sandbox profile breaks digest verification
    let mut plan_tampered = plan.clone();
    plan_tampered.sandbox_profile = "unconfined-host".to_string();
    assert!(!plan_tampered.verify_plan_digest());
}

#[test]
fn test_frozen_invariants_tampering_detection() {
    let plan = create_sample_plan();
    let mut candidate_plan = plan.clone();

    // 1. Identical plan passes frozen assertion
    assert!(plan.assert_frozen_invariants(&candidate_plan).is_ok());

    // 2. Candidate attempts to weaken policy digest
    candidate_plan.policy_digest = Digest32([99u8; 32]);
    candidate_plan.plan_digest = candidate_plan.compute_plan_digest();
    match plan.assert_frozen_invariants(&candidate_plan) {
        Err(EvaluationError::PlanTamperingDetected(_)) => {}
        other => panic!("Expected PlanTamperingDetected, got {:?}", other),
    }

    // 3. Candidate attempts to remove a required evaluator
    let mut candidate_no_eval = plan.clone();
    candidate_no_eval.evaluators.pop();
    candidate_no_eval.plan_digest = candidate_no_eval.compute_plan_digest();
    match plan.assert_frozen_invariants(&candidate_no_eval) {
        Err(EvaluationError::PlanTamperingDetected(_)) => {}
        other => panic!("Expected PlanTamperingDetected, got {:?}", other),
    }
}

#[test]
fn test_evaluation_receipt_p256_signature_and_verification() {
    let signing_key = SigningKey::from_slice(&[42u8; 32]).expect("valid p256 signing key");
    let verifying_key = VerifyingKey::from(&signing_key);

    let receipt = EvaluationReceipt {
        protocol_version: 1,
        evaluation_id: EvaluationId::new_v4(),
        request_digest: Digest32([1u8; 32]),
        subject_digest: Digest32([2u8; 32]),
        plan_digest: Digest32([3u8; 32]),
        evidence_root: Digest32([4u8; 32]),
        outcomes_root: Digest32([5u8; 32]),
        verdict: Verdict::Pass,
        verifier: VerifierIdentity {
            principal_id: "verifier-node-01".to_string(),
            key_id: "key-tpm-primary".to_string(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([6u8; 32]),
            policy_bundle_digest: Digest32([7u8; 32]),
        },
        started_at: Timestamp(1000),
        completed_at: Timestamp(1050),
    };

    let signed: SignedEvaluationReceipt = receipt.sign(&signing_key, CryptographicTier::Tier2SoftwareKey);
    assert_eq!(signed.cryptographic_tier, CryptographicTier::Tier2SoftwareKey);
    assert!(!signed.key_fingerprint.is_empty());

    // 1. Signature verifies successfully
    assert!(signed.verify(&verifying_key).expect("verification failed"));

    // 2. Tampering with receipt verdict causes verification rejection
    let mut tampered = signed.clone();
    tampered.receipt.verdict = Verdict::Fail;
    assert!(tampered.verify(&verifying_key).is_err());

    // 3. Verifying with different key causes rejection
    let other_key = SigningKey::from_slice(&[77u8; 32]).expect("valid p256 other key");
    let other_verifying_key = VerifyingKey::from(&other_key);
    assert!(signed.verify(&other_verifying_key).is_err());
}

#[tokio::test]
async fn test_canary_rollback_harness_invariant_violation_triggers_rollback() {
    let signing_key = SigningKey::from_slice(&[55u8; 32]).expect("valid signing key");
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: "canary-key".to_string(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signing_key,
        CryptographicTier::Tier2SoftwareKey,
    );

    let plan = create_sample_plan();
    let candidate = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([12u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 1024,
    };

    let failing_evaluator = Box::new(MockEvaluator {
        id: "alpha-unslop".to_string(),
        status: EvaluatorStatus::Failed,
        findings: vec![Finding {
            severity: "InvariantViolation".to_string(),
            rule_id: "UNSLOP_EM_DASH".to_string(),
            message: "Detected em dash in docstring".to_string(),
            location: Some("src/lib.rs:42".to_string()),
        }],
    });

    let evaluators: Vec<Box<dyn Evaluator>> = vec![failing_evaluator];
    let rollback_executed = Arc::new(AtomicBool::new(false));
    let rollback_clone = rollback_executed.clone();

    let (receipt, outcomes) = harness
        .evaluate_and_enforce(
            &plan,
            &candidate,
            &evaluators,
            Timestamp(100),
            || async move {
                rollback_clone.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("evaluation and enforcement failed");

    // Invariant failure triggers rollback
    assert!(rollback_executed.load(Ordering::SeqCst), "Rollback must execute on invariant violation");
    assert_eq!(receipt.receipt.verdict, Verdict::Fail);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, EvaluatorStatus::Failed);

    let verifying_key = VerifyingKey::from(&harness.signing_key);
    assert!(receipt.verify(&verifying_key).unwrap());
}

#[tokio::test]
async fn test_canary_rollback_harness_success_admits_candidate() {
    let signing_key = SigningKey::from_slice(&[66u8; 32]).expect("valid signing key");
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: "canary-key".to_string(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signing_key,
        CryptographicTier::Tier2SoftwareKey,
    );

    let plan = create_sample_plan();
    let candidate = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([12u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 1024,
    };

    let passing_evaluator = Box::new(MockEvaluator {
        id: "alpha-unslop".to_string(),
        status: EvaluatorStatus::Passed,
        findings: vec![],
    });

    let evaluators: Vec<Box<dyn Evaluator>> = vec![passing_evaluator];
    let rollback_executed = Arc::new(AtomicBool::new(false));
    let rollback_clone = rollback_executed.clone();

    let (receipt, outcomes) = harness
        .evaluate_and_enforce(
            &plan,
            &candidate,
            &evaluators,
            Timestamp(200),
            || async move {
                rollback_clone.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .expect("evaluation and enforcement failed");

    // Success admits candidate without rollback
    assert!(!rollback_executed.load(Ordering::SeqCst), "Rollback must NOT execute on success");
    assert_eq!(receipt.receipt.verdict, Verdict::Pass);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, EvaluatorStatus::Passed);

    let verifying_key = VerifyingKey::from(&harness.signing_key);
    assert!(receipt.verify(&verifying_key).unwrap());
}
