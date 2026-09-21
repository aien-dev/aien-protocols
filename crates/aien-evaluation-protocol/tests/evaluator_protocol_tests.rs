use aien_evaluation_protocol::{
    CanaryRollbackHarness, CryptographicTier, EvaluationError, EvaluationPlan, EvaluationReceipt,
    Evaluator, EvaluatorDescriptor, EvaluatorIdentity, EvaluatorOutcome, EvaluatorStatus, Finding,
    Measurement, SignedEvaluationReceipt, SoftwareP256Signer, TpmP256Signer, Verdict,
    VerifierIdentity, VerifierSigner,
};
use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct MockEvaluator {
    id: String,
    version: String,
    status: EvaluatorStatus,
    findings: Vec<Finding>,
}

#[async_trait::async_trait]
impl Evaluator for MockEvaluator {
    fn descriptor(&self) -> EvaluatorDescriptor {
        EvaluatorDescriptor {
            evaluator_id: self.id.clone(),
            version: self.version.clone(),
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
                version: self.version.clone(),
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

    let mut plan_tampered = plan.clone();
    plan_tampered.sandbox_profile = "unconfined-host".to_string();
    assert!(!plan_tampered.verify_plan_digest());
}

#[test]
fn test_frozen_invariants_tampering_detection() {
    let plan = create_sample_plan();
    let mut candidate_plan = plan.clone();

    assert!(plan.assert_frozen_invariants(&candidate_plan).is_ok());

    candidate_plan.policy_digest = Digest32([99u8; 32]);
    candidate_plan.plan_digest = candidate_plan.compute_plan_digest();
    match plan.assert_frozen_invariants(&candidate_plan) {
        Err(EvaluationError::PlanTamperingDetected(_)) => {}
        other => panic!("Expected PlanTamperingDetected, got {:?}", other),
    }
}

#[test]
fn test_typed_signer_tier_enforcement_and_signature_verification() {
    let signing_key = SigningKey::from_slice(&[42u8; 32]).expect("valid p256 signing key");
    let signer = SoftwareP256Signer::new(signing_key);
    assert_eq!(signer.cryptographic_tier(), CryptographicTier::Tier2SoftwareKey);

    let fingerprint = signer.key_fingerprint();
    assert!(!fingerprint.is_empty());

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
            key_id: fingerprint.clone(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([6u8; 32]),
            policy_bundle_digest: Digest32([7u8; 32]),
        },
        started_at: Timestamp(1000),
        completed_at: Timestamp(1050),
    };

    let signed: SignedEvaluationReceipt = receipt.sign_with_signer(&signer).expect("signing failed");
    assert_eq!(signed.cryptographic_tier, CryptographicTier::Tier2SoftwareKey);
    assert_eq!(signed.key_fingerprint, fingerprint);

    let verifying_key = signer.verifying_key();
    assert!(signed.verify(&verifying_key).expect("verification failed"));

    // TPM signer strictly reports Tier 4
    let tpm_key = SigningKey::from_slice(&[43u8; 32]).expect("valid p256 signing key");
    let tpm_signer = TpmP256Signer::new("/dev/tpmrm0".to_string(), tpm_key);
    assert_eq!(tpm_signer.cryptographic_tier(), CryptographicTier::Tier4HardwareTpm);

    // Mismatched verifier key_id fails closed
    let mut mismatched_receipt = receipt.clone();
    mismatched_receipt.verifier.key_id = "bogus-key-id".to_string();
    assert!(matches!(
        mismatched_receipt.sign_with_signer(&signer),
        Err(EvaluationError::KeyIdentityMismatch { .. })
    ));
}

#[tokio::test]
async fn test_canary_rollback_harness_missing_evaluator_fails_closed() {
    let signing_key = SigningKey::from_slice(&[55u8; 32]).expect("valid signing key");
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signer,
    );

    let plan = create_sample_plan(); // Requires "alpha-unslop"
    let candidate = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([12u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 1024,
    };

    // Passing empty evaluator list MUST fail closed with MissingRequiredEvaluator
    let empty_evaluators: Vec<Box<dyn Evaluator>> = vec![];
    let res = harness
        .evaluate_and_enforce(
            &plan,
            &candidate,
            &empty_evaluators,
            Timestamp(100),
            || async { Ok(()) },
        )
        .await;

    assert!(matches!(res, Err(EvaluationError::MissingRequiredEvaluator(id)) if id == "alpha-unslop"));
}

#[tokio::test]
async fn test_canary_rollback_harness_version_mismatch_fails_closed() {
    let signing_key = SigningKey::from_slice(&[56u8; 32]).expect("valid signing key");
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signer,
    );

    let plan = create_sample_plan(); // Requires "alpha-unslop" version 1.0.0
    let candidate = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([12u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 1024,
    };

    let wrong_version_eval = Box::new(MockEvaluator {
        id: "alpha-unslop".to_string(),
        version: "0.9.0".to_string(), // Mismatch!
        status: EvaluatorStatus::Passed,
        findings: vec![],
    });

    let evaluators: Vec<Box<dyn Evaluator>> = vec![wrong_version_eval];
    let res = harness
        .evaluate_and_enforce(
            &plan,
            &candidate,
            &evaluators,
            Timestamp(100),
            || async { Ok(()) },
        )
        .await;

    assert!(matches!(res, Err(EvaluationError::EvaluatorVersionMismatch { .. })));
}

#[tokio::test]
async fn test_canary_rollback_harness_invariant_violation_triggers_rollback() {
    let signing_key = SigningKey::from_slice(&[57u8; 32]).expect("valid signing key");
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signer.clone(),
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
        version: "1.0.0".to_string(),
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

    assert!(rollback_executed.load(Ordering::SeqCst));
    assert_eq!(receipt.receipt.verdict, Verdict::Fail);
    assert_eq!(outcomes.len(), 1);

    let verifying_key = signer.verifying_key();
    assert!(receipt.verify(&verifying_key).unwrap());
}

#[tokio::test]
async fn test_canary_rollback_harness_success_admits_candidate() {
    let signing_key = SigningKey::from_slice(&[58u8; 32]).expect("valid signing key");
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let harness = CanaryRollbackHarness::new(
        VerifierIdentity {
            principal_id: "canary-verifier".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([10u8; 32]),
            policy_bundle_digest: Digest32([11u8; 32]),
        },
        signer.clone(),
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
        version: "1.0.0".to_string(),
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

    assert!(!rollback_executed.load(Ordering::SeqCst));
    assert_eq!(receipt.receipt.verdict, Verdict::Pass);
    assert_eq!(outcomes.len(), 1);

    let verifying_key = signer.verifying_key();
    assert!(receipt.verify(&verifying_key).unwrap());
}
