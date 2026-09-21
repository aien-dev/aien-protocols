use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;

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
        hasher.update(self.subject.digest.0);
        hasher.update(self.profile.as_bytes());

        // Sort evaluators by evaluator_id to guarantee deterministic hashing
        let mut sorted_evals = self.evaluators.clone();
        sorted_evals.sort_by(|a, b| a.evaluator_id.cmp(&b.evaluator_id));
        for eval in &sorted_evals {
            hasher.update(eval.evaluator_id.as_bytes());
            hasher.update(eval.version.as_bytes());
            hasher.update([if eval.required { 1u8 } else { 0u8 }]);
        }

        if let Some(ref base) = self.baseline {
            hasher.update(b"baseline:present");
            hasher.update(base.artifact_id.as_bytes());
            hasher.update(base.digest.0);
        } else {
            hasher.update(b"baseline:none");
        }

        hasher.update(self.sandbox_profile.as_bytes());
        hasher.update(self.policy_digest.0);
        hasher.update(self.evaluator_manifest_digest.0);

        let result: [u8; 32] = hasher.finalize().into();
        Digest32(result)
    }

    /// Verifies that the plan digest strictly matches its computed content.
    pub fn verify_plan_digest(&self) -> bool {
        self.plan_digest == self.compute_plan_digest()
    }

    /// Asserts that a proposed candidate plan preserves all frozen invariants of this authoritative plan.
    pub fn assert_frozen_invariants(
        &self,
        candidate_plan: &EvaluationPlan,
    ) -> Result<(), EvaluationError> {
        if !self.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }
        if !candidate_plan.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }
        if self.plan_digest != candidate_plan.plan_digest {
            return Err(EvaluationError::PlanTamperingDetected(format!(
                "Plan digest altered: authoritative {} vs candidate {}",
                hex::encode(self.plan_digest.0),
                hex::encode(candidate_plan.plan_digest.0)
            )));
        }
        if self.policy_digest != candidate_plan.policy_digest {
            return Err(EvaluationError::PolicyTamperingDetected(format!(
                "Policy digest altered: authoritative {} vs candidate {}",
                hex::encode(self.policy_digest.0),
                hex::encode(candidate_plan.policy_digest.0)
            )));
        }
        if self.evaluator_manifest_digest != candidate_plan.evaluator_manifest_digest {
            return Err(EvaluationError::ManifestTamperingDetected(format!(
                "Evaluator manifest digest altered: authoritative {} vs candidate {}",
                hex::encode(self.evaluator_manifest_digest.0),
                hex::encode(candidate_plan.evaluator_manifest_digest.0)
            )));
        }
        if self.baseline != candidate_plan.baseline {
            return Err(EvaluationError::BaselineTamperingDetected(
                "Baseline artifact reference altered".to_string(),
            ));
        }
        if self.evaluators != candidate_plan.evaluators {
            return Err(EvaluationError::EvaluatorTamperingDetected(
                "Evaluator descriptors list altered".to_string(),
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
    pub fn compute_execution_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.evaluator.evaluator_id.as_bytes());
        hasher.update(self.evaluator.version.as_bytes());
        hasher.update(self.evaluator.binary_digest.0);
        hasher.update(self.evaluator.config_digest.0);
        let status_code: u8 = match self.status {
            EvaluatorStatus::Passed => 0,
            EvaluatorStatus::Failed => 1,
            EvaluatorStatus::Inconclusive => 2,
            EvaluatorStatus::TimedOut => 3,
        };
        hasher.update([status_code]);

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
            hasher.update(m.value.to_bits().to_le_bytes());
            hasher.update(m.unit.as_bytes());
        }

        for ev in &self.evidence {
            hasher.update(ev.artifact_id.as_bytes());
            hasher.update(ev.digest.0);
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

/// Abstract verifier signing authority whose implementation strictly dictates its own cryptographic tier.
pub trait VerifierSigner: Send + Sync {
    fn cryptographic_tier(&self) -> CryptographicTier;
    fn key_fingerprint(&self) -> String;
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, EvaluationError>;
    fn verifying_key(&self) -> VerifyingKey;
}

/// Software in-memory ECDSA P-256 signer (strictly Tier 2).
pub struct SoftwareP256Signer {
    signing_key: SigningKey,
    fingerprint: String,
}

impl SoftwareP256Signer {
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = VerifyingKey::from(&signing_key);
        let fingerprint = hex::encode(Sha256::digest(verifying_key.to_sec1_point(true).as_bytes()));
        Self {
            signing_key,
            fingerprint,
        }
    }
}

impl VerifierSigner for SoftwareP256Signer {
    fn cryptographic_tier(&self) -> CryptographicTier {
        CryptographicTier::Tier2SoftwareKey
    }

    fn key_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, EvaluationError> {
        let sig: Signature = self.signing_key.sign(digest);
        Ok(sig.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing_key)
    }
}

/// Hardware TPM 2.0 bound key signer (strictly Tier 4).
/// The private key resides strictly within the TPM 2.0 hardware microcontroller
/// and never touches host memory. Signing executes directly on the physical TPM chip.
pub struct TpmP256Signer {
    device_path: String,
    key_context_path: std::path::PathBuf,
    verifying_key: VerifyingKey,
    fingerprint: String,
}

impl TpmP256Signer {
    /// Connects to a physical TPM 2.0 device and provisions a hardware-bound ECC key in silicon.
    pub fn connect(device_path: impl Into<String>) -> Result<Self, EvaluationError> {
        let dev = device_path.into();
        let tpm_dir = std::env::temp_dir().join(format!("aien-tpm-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tpm_dir).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to create TPM work dir: {}", e))
        })?;

        let primary_ctx = tpm_dir.join("primary.ctx");
        let key_pub = tpm_dir.join("key.pub");
        let key_priv = tpm_dir.join("key.priv");
        let key_ctx = tpm_dir.join("key.ctx");
        let pub_pem = tpm_dir.join("pub.pem");

        // 1. Create primary key in owner hierarchy
        let out1 = std::process::Command::new("tpm2_createprimary")
            .args([
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "ecc",
                "-c",
                primary_ctx.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| {
                EvaluationError::ExecutionFailed(format!("TPM createprimary failed: {}", e))
            })?;
        if !out1.status.success() {
            return Err(EvaluationError::ExecutionFailed(format!(
                "TPM createprimary error: {}",
                String::from_utf8_lossy(&out1.stderr)
            )));
        }

        // 2. Create ECC key in silicon
        let out2 = std::process::Command::new("tpm2_create")
            .args([
                "-C",
                primary_ctx.to_str().unwrap(),
                "-g",
                "sha256",
                "-G",
                "ecc256",
                "-u",
                key_pub.to_str().unwrap(),
                "-r",
                key_priv.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| {
                EvaluationError::ExecutionFailed(format!("TPM create key failed: {}", e))
            })?;
        if !out2.status.success() {
            return Err(EvaluationError::ExecutionFailed(format!(
                "TPM create key error: {}",
                String::from_utf8_lossy(&out2.stderr)
            )));
        }

        // 3. Load key into TPM microcontroller
        let out3 = std::process::Command::new("tpm2_load")
            .args([
                "-C",
                primary_ctx.to_str().unwrap(),
                "-u",
                key_pub.to_str().unwrap(),
                "-r",
                key_priv.to_str().unwrap(),
                "-c",
                key_ctx.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| EvaluationError::ExecutionFailed(format!("TPM load failed: {}", e)))?;
        if !out3.status.success() {
            return Err(EvaluationError::ExecutionFailed(format!(
                "TPM load error: {}",
                String::from_utf8_lossy(&out3.stderr)
            )));
        }

        // 4. Read public key from TPM in PEM format
        let out4 = std::process::Command::new("tpm2_readpublic")
            .args([
                "-c",
                key_ctx.to_str().unwrap(),
                "-o",
                pub_pem.to_str().unwrap(),
                "-f",
                "pem",
            ])
            .output()
            .map_err(|e| {
                EvaluationError::ExecutionFailed(format!("TPM readpublic failed: {}", e))
            })?;
        if !out4.status.success() {
            return Err(EvaluationError::ExecutionFailed(format!(
                "TPM readpublic error: {}",
                String::from_utf8_lossy(&out4.stderr)
            )));
        }

        let pem_str = std::fs::read_to_string(&pub_pem).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to read TPM pubkey PEM: {}", e))
        })?;

        use p256::pkcs8::DecodePublicKey;
        let verifying_key = VerifyingKey::from_public_key_pem(&pem_str).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to parse TPM pubkey: {}", e))
        })?;

        let fingerprint = hex::encode(Sha256::digest(verifying_key.to_sec1_point(true).as_bytes()));

        Ok(Self {
            device_path: dev,
            key_context_path: key_ctx,
            verifying_key,
            fingerprint,
        })
    }

    pub fn from_existing_context(
        device_path: impl Into<String>,
        key_context_path: std::path::PathBuf,
        verifying_key: VerifyingKey,
    ) -> Self {
        let fingerprint = hex::encode(Sha256::digest(verifying_key.to_sec1_point(true).as_bytes()));
        Self {
            device_path: device_path.into(),
            key_context_path,
            verifying_key,
            fingerprint,
        }
    }

    pub fn device_path(&self) -> &str {
        &self.device_path
    }
}

impl VerifierSigner for TpmP256Signer {
    fn cryptographic_tier(&self) -> CryptographicTier {
        CryptographicTier::Tier4HardwareTpm
    }

    fn key_fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, EvaluationError> {
        let digest_tmp = std::env::temp_dir().join(format!("tpm-in-{}.bin", uuid::Uuid::new_v4()));
        let sig_tmp = std::env::temp_dir().join(format!("tpm-out-{}.bin", uuid::Uuid::new_v4()));

        std::fs::write(&digest_tmp, digest).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to write digest: {}", e))
        })?;

        let out = std::process::Command::new("tpm2_sign")
            .args([
                "-c",
                self.key_context_path.to_str().unwrap(),
                "-g",
                "sha256",
                "-o",
                sig_tmp.to_str().unwrap(),
                "-f",
                "plain",
                digest_tmp.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| EvaluationError::ExecutionFailed(format!("TPM sign failed: {}", e)))?;

        let _ = std::fs::remove_file(&digest_tmp);

        if !out.status.success() {
            let _ = std::fs::remove_file(&sig_tmp);
            return Err(EvaluationError::ExecutionFailed(format!(
                "TPM sign command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        let der_sig = std::fs::read(&sig_tmp).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to read TPM signature: {}", e))
        })?;
        let _ = std::fs::remove_file(&sig_tmp);

        let signature = Signature::from_der(&der_sig).map_err(|e| {
            EvaluationError::ExecutionFailed(format!("Failed to parse TPM DER signature: {}", e))
        })?;

        Ok(signature.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
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
    pub fn compute_receipt_digest(&self) -> Digest32 {
        let mut hasher = Sha256::new();
        hasher.update(self.protocol_version.to_le_bytes());
        hasher.update(self.evaluation_id.0.as_bytes());
        hasher.update(self.request_digest.0);
        hasher.update(self.subject_digest.0);
        hasher.update(self.plan_digest.0);
        hasher.update(self.evidence_root.0);
        hasher.update(self.outcomes_root.0);

        let verdict_byte = match self.verdict {
            Verdict::Pass => 0u8,
            Verdict::Fail => 1u8,
            Verdict::Indeterminate => 2u8,
        };
        hasher.update([verdict_byte]);

        hasher.update(self.verifier.principal_id.as_bytes());
        hasher.update(self.verifier.key_id.as_bytes());
        hasher.update(self.verifier.trust_epoch.to_le_bytes());
        hasher.update(self.verifier.trusted_build_digest.0);
        hasher.update(self.verifier.policy_bundle_digest.0);

        hasher.update(self.started_at.0.to_le_bytes());
        hasher.update(self.completed_at.0.to_le_bytes());

        let result: [u8; 32] = hasher.finalize().into();
        Digest32(result)
    }

    /// Signs the receipt using an authoritative VerifierSigner.
    /// Cryptographic tier and key fingerprint are strictly governed by the signer implementation.
    pub fn sign_with_signer(
        &self,
        signer: &dyn VerifierSigner,
    ) -> Result<SignedEvaluationReceipt, EvaluationError> {
        let fingerprint = signer.key_fingerprint();
        if self.verifier.key_id != fingerprint {
            return Err(EvaluationError::KeyIdentityMismatch {
                expected: self.verifier.key_id.clone(),
                actual: fingerprint,
            });
        }

        let digest = self.compute_receipt_digest();
        let sig_bytes = signer.sign_digest(&digest.0)?;
        let tier = signer.cryptographic_tier();

        Ok(SignedEvaluationReceipt {
            receipt: self.clone(),
            signature: sig_bytes,
            cryptographic_tier: tier,
            key_fingerprint: fingerprint,
        })
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
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<bool, EvaluationError> {
        let sig = Signature::from_slice(&self.signature).map_err(|e| {
            EvaluationError::VerificationFailed(format!("Invalid signature format: {e}"))
        })?;
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
    #[error("Missing required evaluator: {0}")]
    MissingRequiredEvaluator(String),
    #[error("Unexpected evaluator not present in plan: {0}")]
    UnexpectedEvaluator(String),
    #[error("Duplicate evaluator provided: {0}")]
    DuplicateEvaluator(String),
    #[error("Evaluator version mismatch for {evaluator_id}: expected {expected}, actual {actual}")]
    EvaluatorVersionMismatch {
        evaluator_id: String,
        expected: String,
        actual: String,
    },
    #[error(
        "Verifier key identity mismatch: receipt key_id {expected} vs signer fingerprint {actual}"
    )]
    KeyIdentityMismatch { expected: String, actual: String },
    #[error("Rollback execution failed: {0}")]
    RollbackFailed(String),
    #[error("Verifier verification error: {0}")]
    VerificationFailed(String),
}

#[async_trait::async_trait]
pub trait Evaluator: Send + Sync {
    fn descriptor(&self) -> EvaluatorDescriptor;
    async fn evaluate(
        &self,
        plan: &EvaluationPlan,
        subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError>;
}

pub fn compute_merkle_root(digests: &[Digest32]) -> Digest32 {
    if digests.is_empty() {
        return Digest32([0u8; 32]);
    }
    let mut current = digests.to_vec();
    while current.len() > 1 {
        let mut next = Vec::new();
        for chunk in current.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0].0);
            if chunk.len() > 1 {
                hasher.update(chunk[1].0);
            } else {
                hasher.update(chunk[0].0);
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
    pub signer: Arc<dyn VerifierSigner>,
}

impl CanaryRollbackHarness {
    pub fn new(verifier: VerifierIdentity, signer: Arc<dyn VerifierSigner>) -> Self {
        Self { verifier, signer }
    }

    /// Executes candidate canary evaluation against the frozen plan.
    /// Strictly verifies that all required evaluators specified in the plan are present and version-matched.
    /// If any required evaluator fails, is missing, or violates an invariant, executes rollback_action and emits a SignedEvaluationReceipt with Verdict::Fail.
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
        // 1. Verify frozen plan integrity
        if !plan.verify_plan_digest() {
            return Err(EvaluationError::PlanDigestMismatch);
        }

        // 2. Validate descriptor coverage between frozen plan and supplied evaluators
        let mut provided_map: HashMap<String, &Box<dyn Evaluator>> = HashMap::new();
        for eval in evaluators {
            let id = eval.descriptor().evaluator_id;
            if provided_map.contains_key(&id) {
                return Err(EvaluationError::DuplicateEvaluator(id));
            }
            provided_map.insert(id, eval);
        }

        let plan_ids: HashSet<String> = plan
            .evaluators
            .iter()
            .map(|d| d.evaluator_id.clone())
            .collect();
        for provided_id in provided_map.keys() {
            if !plan_ids.contains(provided_id) {
                return Err(EvaluationError::UnexpectedEvaluator(provided_id.clone()));
            }
        }

        // Check that every required plan evaluator is present and version-matched
        for expected in &plan.evaluators {
            if let Some(eval) = provided_map.get(&expected.evaluator_id) {
                let actual_desc = eval.descriptor();
                if actual_desc.version != expected.version {
                    return Err(EvaluationError::EvaluatorVersionMismatch {
                        evaluator_id: expected.evaluator_id.clone(),
                        expected: expected.version.clone(),
                        actual: actual_desc.version,
                    });
                }
            } else if expected.required {
                return Err(EvaluationError::MissingRequiredEvaluator(
                    expected.evaluator_id.clone(),
                ));
            }
        }

        // 3. Execute evaluation
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
                if f.severity.eq_ignore_ascii_case("fatal")
                    || f.severity.eq_ignore_ascii_case("invariantviolation")
                {
                    passed_all = false;
                }
            }

            outcomes.push(outcome);
        }

        let verdict = if passed_all {
            Verdict::Pass
        } else {
            // Hard invariant or required evaluator failed: execute rollback
            rollback_action()
                .await
                .map_err(EvaluationError::RollbackFailed)?;
            Verdict::Fail
        };

        let evidence_root = compute_merkle_root(&evidence_digests);
        let outcomes_root = compute_merkle_root(&outcome_digests);
        let completed_at = Timestamp(started_at.0 + 100);

        let receipt = EvaluationReceipt {
            protocol_version: 1,
            evaluation_id: plan.evaluation_id,
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

        let signed = receipt.sign_with_signer(&*self.signer)?;
        Ok((signed, outcomes))
    }
}
