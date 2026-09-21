use aien_inference_client::HttpInferenceClient;
use aien_inference_protocol::*;
use aien_protocol_types::{Digest32, ProtocolVersion};
use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use uuid::Uuid;

async fn mock_infer(Json(req): Json<InferenceRequest>) -> Json<InferenceResponse> {
    Json(InferenceResponse {
        request_id: req.request_id,
        content: "HTTP server response verified".to_string(),
        finish_reason: "stop".to_string(),
        prompt_tokens: 10,
        completion_tokens: 5,
        context: req.context,
    })
}

async fn mock_branch(Json(req): Json<BranchContextRequest>) -> Json<BranchContextReceipt> {
    let mut child = req.parent_context.clone();
    child.branch_id = req.child_branch_id;
    child.generation = child.generation.next();

    Json(BranchContextReceipt {
        operation_id: req.operation_id,
        child_context: child,
        shared_pages: 8,
        copied_pages: 0,
        lease_expires_at_monotonic: 123456,
    })
}

async fn mock_capabilities() -> Json<InferenceCapabilities> {
    Json(InferenceCapabilities {
        protocol: ProtocolVersion::new(1, 0),
        context_branching: true,
        physical_cow: true,
        streaming: false,
        cancellation: true,
        max_context_tokens: Some(8192),
    })
}

#[tokio::test]
async fn test_http_inference_client_full_wire_lifecycle() {
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_infer))
        .route("/v1/context/branch", post(mock_branch))
        .route("/v1/capabilities", get(mock_capabilities));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client =
        HttpInferenceClient::new(format!("http://{}", addr), Some("test-token".to_string()));

    // 1. Test get_capabilities
    let caps = client
        .get_capabilities()
        .await
        .expect("get_capabilities failed");
    assert!(caps.context_branching);
    assert!(caps.physical_cow);
    assert_eq!(caps.max_context_tokens, Some(8192));

    // 2. Test infer
    let req = InferenceRequest {
        request_id: Uuid::new_v4(),
        model: "atlas-omni".to_string(),
        messages: vec![InferenceMessage {
            role: "user".to_string(),
            content: "hello via HTTP".to_string(),
        }],
        context: None,
        max_tokens: 32,
        temperature: 0.0,
        stop_sequences: vec![],
    };
    let res = client.infer(req).await.expect("infer failed");
    assert_eq!(res.content, "HTTP server response verified");
    assert_eq!(res.completion_tokens, 5);

    // 3. Test branch_context
    let dummy_ctx = InferenceContextRef {
        abi_version: 1,
        context_id: ContextId::new_v4(),
        branch_id: BranchId::new_v4(),
        generation: Generation(1),
        model: ModelFingerprint {
            weights_digest: Digest32::ZERO,
            model_config_digest: Digest32::ZERO,
        },
        tokenizer: TokenizerFingerprint {
            tokenizer_digest: Digest32::ZERO,
        },
        kv_format: KvFormatFingerprint {
            format_version: 1,
            dtype: "BF16".to_string(),
        },
        logical_state_digest: Digest32::ZERO,
        token_count: 100,
        lineage: ContextLineage {
            parent_context: None,
            parent_branch: None,
            parent_digest: None,
            fork_token_index: None,
        },
        isolation: CacheIsolationKey {
            domain_id: Uuid::new_v4(),
            domain_digest: Digest32::ZERO,
        },
        binding: None,
        recovery: ContextRecipeRef {
            recipe_id: Uuid::new_v4(),
            recipe_digest: Digest32::ZERO,
        },
    };

    let branch_req = BranchContextRequest {
        operation_id: Uuid::new_v4(),
        parent_context: dummy_ctx,
        child_branch_id: BranchId::new_v4(),
        isolation: CacheIsolationKey {
            domain_id: Uuid::new_v4(),
            domain_digest: Digest32::ZERO,
        },
    };

    let receipt = client
        .branch_context(branch_req)
        .await
        .expect("branch_context failed");
    assert_eq!(receipt.shared_pages, 8);
    assert_eq!(receipt.copied_pages, 0);
    assert_eq!(receipt.child_context.generation, Generation(2));
}
