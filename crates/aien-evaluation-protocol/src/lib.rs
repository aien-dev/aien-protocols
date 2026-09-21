use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedEvaluationReceipt {
    pub receipt: EvaluationReceipt,
    pub signature: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum EvaluationError {
    #[error("Evaluator execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Plan digest mismatch")]
    PlanDigestMismatch,
    #[error("Verifier verification error: {0}")]
    VerificationFailed(String),
}

#[async_trait::async_trait]
pub trait Evaluator: Send + Sync {
    fn descriptor(&self) -> EvaluatorDescriptor;
    async fn evaluate(&self, plan: &EvaluationPlan, subject: &ArtifactRef) -> Result<EvaluatorOutcome, EvaluationError>;
}
