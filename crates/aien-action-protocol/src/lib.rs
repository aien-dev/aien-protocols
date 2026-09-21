use aien_protocol_types::{ActionId, AgentId, Digest32, RunId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: String,
    pub scope: String,
    pub granted_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContainmentState {
    pub isolated_network: bool,
    pub read_only_fs: bool,
    pub seccomp_profile: String,
    pub allowed_subprocesses: Vec<String>,
}

impl Default for ContainmentState {
    fn default() -> Self {
        Self {
            isolated_network: true,
            read_only_fs: true,
            seccomp_profile: "strict".to_string(),
            allowed_subprocesses: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    pub action_id: ActionId,
    pub run_id: RunId,
    pub agent_id: AgentId,
    pub capability: String,
    pub parameters: serde_json::Value,
    pub timestamp: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionAuthorization {
    pub authorization_id: uuid::Uuid,
    pub action_id: ActionId,
    pub approved_by: String,
    pub granted_capabilities: Vec<CapabilityGrant>,
    pub timestamp: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionReceipt {
    pub receipt_id: uuid::Uuid,
    pub action_id: ActionId,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub execution_digest: Digest32,
    pub completed_at: Timestamp,
}
