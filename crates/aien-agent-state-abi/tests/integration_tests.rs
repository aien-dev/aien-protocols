use aien_action_protocol::{CapabilityGrant, ContainmentState};
use aien_agent_state_abi::*;
use aien_inference_client::MockInferenceClient;
use aien_inference_protocol::*;
use aien_protocol_types::*;
use aien_provenance::compute_sha256;

#[test]
fn test_agent_state_roundtrip_and_lineage_verification() {
    let agent_id = AgentId::new_v4();
    let session_id = SessionId::new_v4();
    let initial_timestamp = Timestamp::from_micros(1700000000);

    let initial_state = AgentState {
        abi_version: ProtocolVersion::new(1, 0),
        agent: AgentIdentity {
            agent_id,
            name: "Atlas-Sovereign".to_string(),
            model_profile: "GB10-Grace-Blackwell".to_string(),
            created_at: initial_timestamp,
        },
        session: SessionState {
            session_id,
            title: "Autonomous Agent State ABI Verification".to_string(),
            created_at: initial_timestamp,
            closed_at: None,
        },
        objective: Some(Objective {
            objective_id: uuid::Uuid::new_v4(),
            description: "Verify agent state ABI transitions".to_string(),
            success_criteria: vec!["Deterministic state hash".to_string(), "Zero unslop".to_string()],
        }),
        context: ContextState {
            conversation: Vec::new(),
            pinned: Vec::new(),
            summaries: Vec::new(),
            cortex: Vec::new(),
            inference: None,
        },
        authority: AuthorityState {
            principal: uuid::Uuid::new_v4(),
            policy_profile: "autonomous-strict".to_string(),
            capabilities: vec![CapabilityGrant {
                capability: "shell.execute".to_string(),
                scope: "sandbox:/tmp".to_string(),
                granted_at: initial_timestamp,
                expires_at: None,
            }],
            restrictions: vec!["zero_network_leak".to_string()],
            containment: ContainmentState::default(),
        },
        budget: ResourceBudget {
            max_tokens: Some(8192),
            max_cost_micro_usd: None,
            max_duration_seconds: Some(120),
            max_subagents: Some(16),
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

    let initial_digest = initial_state.compute_digest().expect("Failed to compute initial digest");
    assert_ne!(initial_digest, Digest32::ZERO);

    // Transition 1: RunStarted
    let run_id = RunId::new_v4();
    let event1 = AgentStateEvent {
        abi_version: ProtocolVersion::new(1, 0),
        event_id: EventId::new_v4(),
        agent_id,
        session_id,
        run_id: Some(run_id),
        sequence: SequenceNumber(2),
        timestamp: Timestamp::from_micros(1700000050),
        previous_state: initial_digest,
        event: AgentEvent::RunStarted(run_id),
        resulting_state: Digest32::ZERO, // updated below
    };

    let mut state_after_run = initial_state.clone();
    state_after_run.sequence = SequenceNumber(2);
    state_after_run.execution.active_run = Some(run_id);
    state_after_run.execution.status = AgentExecutionStatus::Running;
    state_after_run.execution.last_event = Some(event1.event_id);
    let digest_after_run = state_after_run.compute_digest().unwrap();
    assert_ne!(initial_digest, digest_after_run);

    // Verify state can be serialized to and from JSON
    let json_str = serde_json::to_string_pretty(&state_after_run).unwrap();
    let deserialized: AgentState = serde_json::from_str(&json_str).unwrap();
    assert_eq!(state_after_run, deserialized);
    assert_eq!(deserialized.compute_digest().unwrap(), digest_after_run);
}

#[tokio::test]
async fn test_inference_client_cow_branching_contract() {
    let client = MockInferenceClient::new();
    let parent_context = InferenceContextRef {
        abi_version: 1,
        context_id: ContextId::new_v4(),
        branch_id: BranchId::new_v4(),
        generation: Generation(1),
        model: ModelFingerprint {
            weights_digest: compute_sha256(b"tinyllama-1.1b-bf16"),
            model_config_digest: compute_sha256(b"config-v1"),
        },
        tokenizer: TokenizerFingerprint {
            tokenizer_digest: compute_sha256(b"tokenizer-v1"),
        },
        kv_format: KvFormatFingerprint {
            format_version: 1,
            dtype: "BF16".to_string(),
        },
        logical_state_digest: compute_sha256(b"logical-tokens-root"),
        token_count: 128,
        lineage: ContextLineage {
            parent_context: None,
            parent_branch: None,
            parent_digest: None,
            fork_token_index: None,
        },
        isolation: CacheIsolationKey {
            domain_id: uuid::Uuid::new_v4(),
            domain_digest: compute_sha256(b"tenant-sovereign"),
        },
        binding: None,
        recovery: ContextRecipeRef {
            recipe_id: uuid::Uuid::new_v4(),
            recipe_digest: compute_sha256(b"recipe-data"),
        },
    };

    let child_branch_id = BranchId::new_v4();
    let branch_req = BranchContextRequest {
        operation_id: uuid::Uuid::new_v4(),
        parent_context: parent_context.clone(),
        child_branch_id,
        isolation: parent_context.isolation,
    };

    let receipt = client.branch_context(branch_req).await.expect("Failed to branch context");
    assert_eq!(receipt.child_context.branch_id, child_branch_id);
    assert_eq!(receipt.child_context.generation, Generation(2));
    assert_eq!(receipt.child_context.lineage.parent_context, Some(parent_context.context_id));
    assert_eq!(receipt.child_context.lineage.parent_branch, Some(parent_context.branch_id));
    assert_eq!(receipt.shared_pages, 10);
    assert_eq!(receipt.copied_pages, 0);
}
