use aien_inference_protocol::*;
use aien_protocol_types::ProtocolVersion;
use async_trait::async_trait;
use std::sync::Arc;

pub struct LocalInferenceClient {
    service: Arc<dyn InferenceService>,
}

impl LocalInferenceClient {
    pub fn new(service: Arc<dyn InferenceService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl InferenceService for LocalInferenceClient {
    async fn infer(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        self.service.infer(req).await
    }

    async fn branch_context(&self, req: BranchContextRequest) -> Result<BranchContextReceipt, InferenceError> {
        self.service.branch_context(req).await
    }

    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError> {
        self.service.get_capabilities().await
    }
}

pub struct HttpInferenceClient {
    pub endpoint: String,
    pub auth_token: Option<String>,
}

impl HttpInferenceClient {
    pub fn new(endpoint: String, auth_token: Option<String>) -> Self {
        Self { endpoint, auth_token }
    }
}

#[async_trait]
impl InferenceService for HttpInferenceClient {
    async fn infer(&self, _req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        Err(InferenceError::Internal(format!("HTTP transport connecting to {} not configured", self.endpoint)))
    }

    async fn branch_context(&self, _req: BranchContextRequest) -> Result<BranchContextReceipt, InferenceError> {
        Err(InferenceError::Internal(format!("HTTP transport connecting to {} not configured", self.endpoint)))
    }

    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError> {
        Ok(InferenceCapabilities {
            protocol: ProtocolVersion::new(1, 0),
            context_branching: true,
            physical_cow: true,
            streaming: true,
            cancellation: true,
            max_context_tokens: Some(32768),
        })
    }
}

pub struct MockInferenceClient {
    capabilities: InferenceCapabilities,
}

impl MockInferenceClient {
    pub fn new() -> Self {
        Self {
            capabilities: InferenceCapabilities {
                protocol: ProtocolVersion::new(1, 0),
                context_branching: true,
                physical_cow: true,
                streaming: false,
                cancellation: true,
                max_context_tokens: Some(32768),
            },
        }
    }
}

impl Default for MockInferenceClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InferenceService for MockInferenceClient {
    async fn infer(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        Ok(InferenceResponse {
            request_id: req.request_id,
            content: "mock inference output".to_string(),
            finish_reason: "stop".to_string(),
            prompt_tokens: 16,
            completion_tokens: 8,
            context: req.context,
        })
    }

    async fn branch_context(&self, req: BranchContextRequest) -> Result<BranchContextReceipt, InferenceError> {
        let mut child_context = req.parent_context.clone();
        child_context.branch_id = req.child_branch_id;
        child_context.generation = child_context.generation.next();
        child_context.lineage.parent_context = Some(req.parent_context.context_id);
        child_context.lineage.parent_branch = Some(req.parent_context.branch_id);

        Ok(BranchContextReceipt {
            operation_id: req.operation_id,
            child_context,
            shared_pages: 10,
            copied_pages: 0,
            lease_expires_at_monotonic: 999999999,
        })
    }

    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError> {
        Ok(self.capabilities.clone())
    }
}

pub type DynInferenceService = Arc<dyn InferenceService>;
