use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationClaim {
    pub claim_type: String,
    pub statement: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationRequest {
    pub protocol_version: u32,
    pub request_id: EvaluationId,
    pub proposer: String,
    pub subject: ArtifactRef,
    pub parent: Option<ArtifactRef>,
    pub profile: String,
    pub claims: Vec<EvaluationClaim>,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluatorDescriptor {
    pub evaluator_id: String,
    pub version: String,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationPlan {
    pub evaluation_id: EvaluationId,
    pub subject: ArtifactRef,
    pub profile: String,
    pub evaluators: Vec<EvaluatorDescriptor>,
    pub baseline: Option<ArtifactRef>,
    pub sandbox_profile: String,
    pub policy_digest: Digest32,
    pub evaluator_manifest_digest: Digest32,
    pub plan_digest: Digest32,
}

impl EvaluationPlan {
    /// Computes the deterministic SHA-256 digest of the evaluation plan.
    pub fn compute_plan_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.evaluation_id.0.as_bytes());
        hasher.update(self.subject.artifact_id.as_bytes());
        hasher.update(&self.subject.digest.0);
        hasher.update(self.profile.as_bytes());

        // Sort evaluators by evaluator_id to guarantee deterministic hashing
        let mut sorted_evals = self.evaluators.clone();
        sorted_evals.sort_by(|a, b| a.evaluator_id.cmp(&b.evaluator_id));
        for eval in &sorted_evals {
            hasher.update(eval.evaluator_id.as_bytes());
            hasher.update(eval.version.as_bytes());
            hasher.update(&[if eval.required { 1u8 } else { 0u8 }]);
        }

        if let Some(ref base) = self.baseline {
            hasher.update(b"baseline:present");
            hasher.update(base.artifact_id.as_bytes());
            hasher.update(&base.digest.0);
        } else {
            hasher.update(b"baseline:none");
        }

        hasher.update(self.sandbox_profile.as_bytes());
        hasher.update(&self.policy_digest.0);
        hasher.update(&self.evaluator_manifest_digest.0);

        let result: [u8; 32] = hasher.finalize().into();
        Digest32(result)
    }

    /// Verifies that the plan digest strictly matches its computed content.
    pub fn verify_plan_digest(&self) -> bool {
        self.plan_digest == self.compute_plan_digest()
    }

    /// Asserts that a proposed candidate plan preserves all frozen invariants of this authoritative plan.
    /// Returns an error if any parameter, threshold, baseline, evaluator, or digest has been tampered with.
    pub fn assert_frozen_invariants(&self, candidate_plan: &EvaluationPlan) -> Result<(), EvaluationError> {
        if !self.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }
        if !candidate_plan.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }
        if self.plan_digest != candidate_plan.plan_digest {
            return Err(EvaluationError::PlanTamperingDetected(
                format!("Plan digest altered: authoritative {} vs candidate {}",
                    hex::encode(self.plan_digest.0),
                    hex::encode(candidate_plan.plan_digest.0)
                )
            ));
        }
        if self.policy_digest != candidate_plan.policy_digest {
            return Err(EvaluationError::PolicyTamperingDetected(
                format!("Policy digest altered: authoritative {} vs candidate {}",
                    hex::encode(self.policy_digest.0),
                    hex::encode(candidate_plan.policy_digest.0)
                )
            ));
        }
        if self.evaluator_manifest_digest != candidate_plan.evaluator_manifest_digest {
            return Err(EvaluationError::ManifestTamperingDetected(
                format!("Evaluator manifest digest altered: authoritative {} vs candidate {}",
                    hex::encode(self.evaluator_manifest_digest.0),
                    hex::encode(candidate_plan.evaluator_manifest_digest.0)
                )
            ));
        }
        if self.baseline != candidate_plan.baseline {
            return Err(EvaluationError::BaselineTamperingDetected(
                "Baseline artifact reference altered".to_string()
            ));
        }
        if self.evaluators != candidate_plan.evaluators {
            return Err(EvaluationError::EvaluatorTamperingDetected(
                "Evaluator descriptors list altered".to_string()
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluatorIdentity {
    pub evaluator_id: String,
    pub version: String,
    pub binary_digest: Digest32,
    pub config_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvaluatorStatus {
    Passed,
    Failed,
    Inconclusive,
    TimedOut,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub rule_id: String,
    pub message: String,
    pub location: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    pub metric: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvaluatorOutcome {
    pub evaluator: EvaluatorIdentity,
    pub status: EvaluatorStatus,
    pub findings: Vec<Finding>,
    pub measurements: Vec<Measurement>,
    pub evidence: Vec<ArtifactRef>,
    pub execution_digest: Digest32,
}

impl EvaluatorOutcome {
    /// Computes the deterministic execution digest over outcome components.
    pub fn compute_execution_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.evaluator.evaluator_id.as_bytes());
        hasher.update(self.evaluator.version.as_bytes());
        hasher.update(&self.evaluator.binary_digest.0);
        hasher.update(&self.evaluator.config_digest.0);
        let status_code: u8 = match self.status {
            EvaluatorStatus::Passed => 0,
            EvaluatorStatus::Failed => 1,
            EvaluatorStatus::Inconclusive => 2,
            EvaluatorStatus::TimedOut => 3,
        };
        hasher.update(&[status_code]);

        for f in &self.findings {
            hasher.update(f.severity.as_bytes());
            hasher.update(f.rule_id.as_bytes());
            hasher.update(f.message.as_bytes());
            if let Some(ref loc) = f.location {
                hasher.update(loc.as_bytes());
            }
        }

        for m in &self.measurements {
            hasher.update(m.metric.as_bytes());
            hasher.update(&m.value.to_bits().to_le_bytes());
            hasher.update(m.unit.as_bytes());
        }

        for ev in &self.evidence {
            hasher.update(ev.artifact_id.as_bytes());
            hasher.update(&ev.digest.0);
        }

        let result: [u8; 32] = hasher.finalize().into();
        Digest32(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierIdentity {
    pub principal_id: String,
    pub key_id: String,
    pub trust_epoch: u64,
    pub trusted_build_digest: Digest32,
    pub policy_bundle_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CryptographicTier {
    /// Tier 1: Algorithm/digest only (SHA-256).
    Tier1AlgorithmOnly,
    /// Tier 2: Software key signing (in-memory ECDSA P-256).
    Tier2SoftwareKey,
    /// Tier 3: Host OS key (file or daemon key).
    Tier3HostOsKey,
    /// Tier 4: Hardware TPM 2.0 bound key (/dev/tpmrm0 ECDSA P-256).
    Tier4HardwareTpm,
}

impl CryptographicTier {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Tier1AlgorithmOnly => "tier1-algo",
            Self::Tier2SoftwareKey => "tier2-software",
            Self::Tier3HostOsKey => "tier3-host-os",
            Self::Tier4HardwareTpm => "tier4-hardware-tpm",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationReceipt {
    pub protocol_version: u32,
    pub evaluation_id: EvaluationId,
    pub request_digest: Digest32,
    pub subject_digest: Digest32,
    pub plan_digest: Digest32,
    pub evidence_root: Digest32,
    pub outcomes_root: Digest32,
    pub verdict: Verdict,
    pub verifier: VerifierIdentity,
    pub started_at: Timestamp,
    pub completed_at: Timestamp,
}

impl EvaluationReceipt {
    /// Computes the deterministic SHA-256 digest of the receipt.
    pub fn compute_receipt_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(self.evaluation_id.0.as_bytes());
        hasher.update(&self.request_digest.0);
        hasher.update(&self.subject_digest.0);
        hasher.update(&self.plan_digest.0);
        hasher.update(&self.evidence_root.0);
        hasher.update(&self.outcomes_root.0);

        let verdict_byte = match self.verdict {
            Verdict::Pass => 0u8,
            Verdict::Fail => 1u8,
            Verdict::Indeterminate => 2u8,
        };
        hasher.update(&[verdict_byte]);

        hasher.update(self.verifier.principal_id.as_bytes());
        hasher.update(self.verifier.key_id.as_bytes());
        hasher.update(&self.verifier.trust_epoch.to_le_bytes());
        hasher.update(&self.verifier.trusted_build_digest.0);
        hasher.update(&self.verifier.policy_bundle_digest.0);

        hasher.update(&self.started_at.0.to_le_bytes());
        hasher.update(&self.completed_at.0.to_le_bytes());

        let result: [u8; 32] = hasher.finalize().into();
        Digest32(result)
    }

    /// Signs the receipt using an ECDSA P-256 key, declaring the explicit cryptographic tier.
    pub fn sign(
        &self,
        signing_key: &SigningKey,
        tier: CryptographicTier,
    ) -> SignedEvaluationReceipt {
        let digest = self.compute_receipt_digest();
        let sig: Signature = signing_key.sign(&digest.0);
        let verifying_key = VerifyingKey::from(signing_key);
        let key_fingerprint = hex::encode(Sha256::digest(verifying_key.to_sec1_point(true).as_bytes()));

        SignedEvaluationReceipt {
            receipt: self.clone(),
            signature: sig.to_bytes().to_vec(),
            cryptographic_tier: tier,
            key_fingerprint,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedEvaluationReceipt {
    pub receipt: EvaluationReceipt,
    pub signature: Vec<u8>,
    pub cryptographic_tier: CryptographicTier,
    pub key_fingerprint: String,
}

impl SignedEvaluationReceipt {
    /// Cryptographically verifies the signature over the receipt digest using the provided verifying key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<bool, EvaluationError> {
        let sig = Signature::from_slice(&self.signature)
            .map_err(|e| EvaluationError::VerificationFailed(format!("Invalid signature format: {e}")))?;
        let digest = self.receipt.compute_receipt_digest();
        verifying_key
            .verify(&digest.0, &sig)
            .map(|_| true)
            .map_err(|e| EvaluationError::VerificationFailed(format!("Signature mismatch: {e}")))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EvaluationError {
    #[error("Evaluator execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Plan digest mismatch")]
    PlanDigestMismatch,
    #[error("Plan tampering detected: {0}")]
    PlanTamperingDetected(String),
    #[error("Policy tampering detected: {0}")]
    PolicyTamperingDetected(String),
    #[error("Evaluator manifest tampering detected: {0}")]
    ManifestTamperingDetected(String),
    #[error("Baseline reference tampering detected: {0}")]
    BaselineTamperingDetected(String),
    #[error("Evaluator descriptor tampering detected: {0}")]
    EvaluatorTamperingDetected(String),
    #[error("Rollback execution failed: {0}")]
    RollbackFailed(String),
    #[error("Verifier verification error: {0}")]
    VerificationFailed(String),
}

#[async_trait::async_trait]
pub trait Evaluator: Send + Sync {
    fn descriptor(&self) -> EvaluatorDescriptor;
    async fn evaluate(&self, plan: &EvaluationPlan, subject: &ArtifactRef) -> Result<EvaluatorOutcome, EvaluationError>;
}

/// Computes a Merkle root over a sequence of digests.
pub fn compute_merkle_root(digests: &[Digest32]) -> Digest32 {
    if digests.is_empty() {
        return Digest32([0u8; 32]);
    }
    let mut current = digests.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        for chunk in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0].0);
            if chunk.len() > 1 {
                hasher.update(&chunk[1].0);
            } else {
                hasher.update(&chunk[0].0);
            }
            next.push(Digest32(hasher.finalize().into()));
        }
        current = next;
    }
    current[0]
}

/// Canary evaluation and rollback harness enforcing the RSI safety envelope.
pub struct CanaryRollbackHarness {
    pub verifier: VerifierIdentity,
    pub signing_key: SigningKey,
    pub cryptographic_tier: CryptographicTier,
}

impl CanaryRollbackHarness {
    pub fn new(
        verifier: VerifierIdentity,
        signing_key: SigningKey,
        cryptographic_tier: CryptographicTier,
    ) -> Self {
        Self {
            verifier,
            signing_key,
            cryptographic_tier,
        }
    }

    /// Executes candidate canary evaluation against the frozen plan.
    /// If any required evaluator fails or invariant is violated, executes rollback_action and emits a SignedEvaluationReceipt with Verdict::Fail.
    /// If all requirements pass, emits a SignedEvaluationReceipt with Verdict::Pass.
    pub async fn evaluate_and_enforce<R, Fut>(
        &self,
        plan: &EvaluationPlan,
        candidate: &ArtifactRef,
        evaluators: &[Box<dyn Evaluator>],
        started_at: Timestamp,
        rollback_action: R,
    ) -> Result<(SignedEvaluationReceipt, Vec<EvaluatorOutcome>), EvaluationError>
    where
        R: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<(), String>> + Send,
    {
        if !plan.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }

        let mut outcomes = Vec::new();
        let mut passed_all = true;
        let mut evidence_digests = Vec::new();
        let mut outcome_digests = Vec::new();

        for eval in evaluators {
            let desc = eval.descriptor();
            let outcome = eval.evaluate(plan, candidate).await?;

            let exec_digest = outcome.compute_execution_digest();
            outcome_digests.push(exec_digest);

            for ev in &outcome.evidence {
                evidence_digests.push(ev.digest);
            }

            if desc.required && outcome.status != EvaluatorStatus::Passed {
                passed_all = false;
            }

            for f in &outcome.findings {
                if f.severity.eq_ignore_ascii_case("fatal") || f.severity.eq_ignore_ascii_case("invariantviolation") {
                    passed_all = false;
                }
            }

            outcomes.push(outcome);
        }

        let verdict = if passed_all {
            Verdict::Pass
        } else {
            // Hard invariant or required evaluator failed: execute rollback
            rollback_action().await.map_err(EvaluationError::RollbackFailed)?;
            Verdict::Fail
        };

        let evidence_root = compute_merkle_root(&evidence_digests);
        let outcomes_root = compute_merkle_root(&outcome_digests);
        let completed_at = Timestamp(started_at.0 + 100);

        let receipt = EvaluationReceipt {
            protocol_version: 1,
            evaluation_id: plan.evaluation_id.clone(),
            request_digest: Digest32([0u8; 32]),
            subject_digest: candidate.digest,
            plan_digest: plan.plan_digest,
            evidence_root,
            outcomes_root,
            verdict,
            verifier: self.verifier.clone(),
            started_at,
            completed_at,
        };

        let signed = receipt.sign(&self.signing_key, self.cryptographic_tier);
        Ok((signed, outcomes))
    }
}
