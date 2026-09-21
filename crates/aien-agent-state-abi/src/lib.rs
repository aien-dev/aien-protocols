use aien_action_protocol::{CapabilityGrant, ContainmentState};
use aien_inference_protocol::InferenceContextRef;
use aien_protocol_types::{
    ActionId, AgentId, ApprovalId, ArtifactRef, Digest32, EventId, ProtocolVersion, RunId,
    SequenceNumber, SessionId, Timestamp,
};
use aien_provenance::compute_canonical_json_digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_id: AgentId,
    pub name: String,
    pub model_profile: String,
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: SessionId,
    pub title: String,
    pub created_at: Timestamp,
    pub closed_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Objective {
    pub objective_id: uuid::Uuid,
    pub description: String,
    pub success_criteria: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageRef {
    pub message_id: uuid::Uuid,
    pub role: String,
    pub digest: Digest32,
    pub token_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRef {
    pub memory_id: uuid::Uuid,
    pub space: String,
    pub canonical_name: String,
    pub digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContextState {
    pub conversation: Vec<MessageRef>,
    pub pinned: Vec<ArtifactRef>,
    pub summaries: Vec<ArtifactRef>,
    pub cortex: Vec<MemoryRef>,
    pub inference: Option<InferenceContextRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityState {
    pub principal: uuid::Uuid,
    pub policy_profile: String,
    pub capabilities: Vec<CapabilityGrant>,
    pub restrictions: Vec<String>,
    pub containment: ContainmentState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_tokens: Option<u64>,
    pub max_cost_micro_usd: Option<u64>,
    pub max_duration_seconds: Option<u64>,
    pub max_subagents: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AgentExecutionStatus {
    Idle,
    Running,
    Suspended,
    AwaitingApproval,
    Terminated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionState {
    pub active_run: Option<RunId>,
    pub status: AgentExecutionStatus,
    pub pending_actions: Vec<ActionId>,
    pub pending_approvals: Vec<ApprovalId>,
    pub last_event: Option<EventId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateRef {
    pub state_id: uuid::Uuid,
    pub digest: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentState {
    pub abi_version: ProtocolVersion,
    pub agent: AgentIdentity,
    pub session: SessionState,
    pub objective: Option<Objective>,
    pub context: ContextState,
    pub authority: AuthorityState,
    pub budget: ResourceBudget,
    pub execution: ExecutionState,
    pub parent: Option<StateRef>,
    pub sequence: SequenceNumber,
}

impl AgentState {
    pub fn compute_digest(&self) -> Result<Digest32, serde_json::Error> {
        compute_canonical_json_digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AgentEvent {
    SessionCreated,
    MessageAdded(MessageRef),
    RunStarted(RunId),
    InferenceRequested(uuid::Uuid),
    InferenceCompleted(uuid::Uuid),
    ActionRequested(ActionId),
    ActionAuthorized(ActionId),
    ActionDenied(ActionId),
    ActionCompleted(ActionId),
    ApprovalRequested(ApprovalId),
    ApprovalResolved(ApprovalId),
    ContextBranched(uuid::Uuid),
    BudgetUpdated(ResourceBudget),
    ContainmentChanged(ContainmentState),
    RunSuspended,
    RunResumed,
    RunCompleted(String),
    SessionClosed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentStateEvent {
    pub abi_version: ProtocolVersion,
    pub event_id: EventId,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub run_id: Option<RunId>,
    pub sequence: SequenceNumber,
    pub timestamp: Timestamp,
    pub previous_state: Digest32,
    pub event: AgentEvent,
    pub resulting_state: Digest32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_state_digest_deterministic() {
        let state = AgentState {
            abi_version: ProtocolVersion::new(1, 0),
            agent: AgentIdentity {
                agent_id: AgentId::new_v4(),
                name: "Atlas".to_string(),
                model_profile: "GB10-MAX-Qwen".to_string(),
                created_at: Timestamp::from_micros(1000),
            },
            session: SessionState {
                session_id: SessionId::new_v4(),
                title: "Test Session".to_string(),
                created_at: Timestamp::from_micros(1000),
                closed_at: None,
            },
            objective: None,
            context: ContextState {
                conversation: Vec::new(),
                pinned: Vec::new(),
                summaries: Vec::new(),
                cortex: Vec::new(),
                inference: None,
            },
            authority: AuthorityState {
                principal: uuid::Uuid::new_v4(),
                policy_profile: "autonomous-safe".to_string(),
                capabilities: Vec::new(),
                restrictions: Vec::new(),
                containment: ContainmentState::default(),
            },
            budget: ResourceBudget {
                max_tokens: Some(4096),
                max_cost_micro_usd: None,
                max_duration_seconds: Some(60),
                max_subagents: Some(4),
            },
            execution: ExecutionState {
                active_run: None,
                status: AgentExecutionStatus::Idle,
                pending_actions: Vec::new(),
                pending_approvals: Vec::new(),
                last_event: None,
            },
            parent: None,
            sequence: SequenceNumber(1),
        };

        let digest1 = state.compute_digest().unwrap();
        let digest2 = state.compute_digest().unwrap();
        assert_eq!(digest1, digest2);
        assert_ne!(digest1, Digest32::ZERO);
    }
}
