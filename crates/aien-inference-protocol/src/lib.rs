use aien_protocol_types::{Digest32, ProtocolVersion};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContextId(pub uuid::Uuid);

impl ContextId {
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BranchId(pub uuid::Uuid);

impl BranchId {
    pub fn new_v4() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Generation(pub u64);

impl Generation {
    pub fn next(&self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelFingerprint {
    pub weights_digest: Digest32,
    pub model_config_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TokenizerFingerprint {
    pub tokenizer_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KvFormatFingerprint {
    pub format_version: u16,
    pub dtype: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextLineage {
    pub parent_context: Option<ContextId>,
    pub parent_branch: Option<BranchId>,
    pub parent_digest: Option<Digest32>,
    pub fork_token_index: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CacheIsolationKey {
    pub domain_id: uuid::Uuid,
    pub domain_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpaqueBindingRef {
    pub engine_id: String,
    pub runtime_epoch: u64,
    pub binding_id: uuid::Uuid,
    pub lease_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextRecipeRef {
    pub recipe_id: uuid::Uuid,
    pub recipe_digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceContextRef {
    pub abi_version: u16,
    pub context_id: ContextId,
    pub branch_id: BranchId,
    pub generation: Generation,
    pub model: ModelFingerprint,
    pub tokenizer: TokenizerFingerprint,
    pub kv_format: KvFormatFingerprint,
    pub logical_state_digest: Digest32,
    pub token_count: u64,
    pub lineage: ContextLineage,
    pub isolation: CacheIsolationKey,
    pub binding: Option<OpaqueBindingRef>,
    pub recovery: ContextRecipeRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MergeStrategy {
    FastForward,
    SelectBranch { branch: BranchId },
    RebuildFrom { recipe: ContextRecipeRef },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub request_id: uuid::Uuid,
    pub model: String,
    pub messages: Vec<InferenceMessage>,
    pub context: Option<InferenceContextRef>,
    pub max_tokens: u32,
    pub temperature: f32,
    pub stop_sequences: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceResponse {
    pub request_id: uuid::Uuid,
    pub content: String,
    pub finish_reason: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub context: Option<InferenceContextRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchContextRequest {
    pub operation_id: uuid::Uuid,
    pub parent_context: InferenceContextRef,
    pub child_branch_id: BranchId,
    pub isolation: CacheIsolationKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchContextReceipt {
    pub operation_id: uuid::Uuid,
    pub child_context: InferenceContextRef,
    pub shared_pages: u32,
    pub copied_pages: u32,
    pub lease_expires_at_monotonic: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceCapabilities {
    pub protocol: ProtocolVersion,
    pub context_branching: bool,
    pub physical_cow: bool,
    pub streaming: bool,
    pub cancellation: bool,
    pub max_context_tokens: Option<u64>,
}

#[derive(thiserror::Error, Debug)]
pub enum InferenceError {
    #[error("Incompatible protocol version: expected {expected}, got {received}")]
    VersionMismatch { expected: String, received: String },
    #[error("Context not found: {0:?}")]
    ContextNotFound(ContextId),
    #[error("Stale generation: expected {expected:?}, got {actual:?}")]
    StaleGeneration {
        expected: Generation,
        actual: Generation,
    },
    #[error("Stale runtime epoch: engine restarted, must reconstruct from recipe")]
    StaleRuntimeEpoch,
    #[error("Cache isolation error: domain unauthorized")]
    IsolationDenied,
    #[error("Resource exhaustion: {0}")]
    ResourceExhausted(String),
    #[error("Internal execution error: {0}")]
    Internal(String),
}

#[async_trait::async_trait]
pub trait InferenceService: Send + Sync {
    async fn infer(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError>;
    async fn branch_context(
        &self,
        req: BranchContextRequest,
    ) -> Result<BranchContextReceipt, InferenceError>;
    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError>;
}
