use aien_inference_protocol::*;
use aien_protocol_types::ProtocolVersion;
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use std::sync::Arc;
use std::time::Duration;

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

    async fn branch_context(
        &self,
        req: BranchContextRequest,
    ) -> Result<BranchContextReceipt, InferenceError> {
        self.service.branch_context(req).await
    }

    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError> {
        self.service.get_capabilities().await
    }
}

/// Real HTTP transport adapter implementing InferenceService over remote REST endpoints.
pub struct HttpInferenceClient {
    pub endpoint: String,
    pub auth_token: Option<String>,
    client: Client,
}

impl HttpInferenceClient {
    pub fn new(endpoint: String, auth_token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            endpoint,
            auth_token,
            client,
        }
    }

    pub fn with_client(endpoint: String, auth_token: Option<String>, client: Client) -> Self {
        Self {
            endpoint,
            auth_token,
            client,
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.endpoint.trim_end_matches('/');
        let rel = path.trim_start_matches('/');
        format!("{}/{}", base, rel)
    }

    fn map_http_error(status: StatusCode, body: &str) -> InferenceError {
        match status {
            StatusCode::NOT_FOUND => {
                InferenceError::Internal(format!("Resource not found (404): {}", body))
            }
            StatusCode::CONFLICT => InferenceError::StaleRuntimeEpoch,
            StatusCode::TOO_MANY_REQUESTS => InferenceError::ResourceExhausted(format!(
                "Capacity or rate limit exceeded (429): {}",
                body
            )),
            _ => InferenceError::Internal(format!("HTTP {}: {}", status, body)),
        }
    }
}

#[async_trait]
impl InferenceService for HttpInferenceClient {
    async fn infer(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        if self.endpoint.is_empty() {
            return Err(InferenceError::Internal(
                "HTTP transport endpoint is empty".to_string(),
            ));
        }

        let url = self.url("v1/chat/completions");
        let mut builder = self.client.post(&url).json(&req);

        if let Some(token) = &self.auth_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let resp = builder.send().await.map_err(|e| {
            InferenceError::Internal(format!("HTTP request failed to {}: {}", url, e))
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_http_error(status, &body));
        }

        resp.json::<InferenceResponse>().await.map_err(|e| {
            InferenceError::Internal(format!("Failed to parse InferenceResponse JSON: {}", e))
        })
    }

    async fn branch_context(
        &self,
        req: BranchContextRequest,
    ) -> Result<BranchContextReceipt, InferenceError> {
        if self.endpoint.is_empty() {
            return Err(InferenceError::Internal(
                "HTTP transport endpoint is empty".to_string(),
            ));
        }

        let url = self.url("v1/context/branch");
        let mut builder = self.client.post(&url).json(&req);

        if let Some(token) = &self.auth_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let resp = builder.send().await.map_err(|e| {
            InferenceError::Internal(format!("HTTP request failed to {}: {}", url, e))
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_http_error(status, &body));
        }

        resp.json::<BranchContextReceipt>().await.map_err(|e| {
            InferenceError::Internal(format!("Failed to parse BranchContextReceipt JSON: {}", e))
        })
    }

    async fn get_capabilities(&self) -> Result<InferenceCapabilities, InferenceError> {
        if self.endpoint.is_empty() {
            return Err(InferenceError::Internal(
                "HTTP transport endpoint is empty".to_string(),
            ));
        }

        let url = self.url("v1/capabilities");
        let mut builder = self.client.get(&url);

        if let Some(token) = &self.auth_token {
            builder = builder.header("Authorization", format!("Bearer {}", token));
        }

        let resp = builder.send().await.map_err(|e| {
            InferenceError::Internal(format!("HTTP request failed to {}: {}", url, e))
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Self::map_http_error(status, &body));
        }

        resp.json::<InferenceCapabilities>().await.map_err(|e| {
            InferenceError::Internal(format!("Failed to parse InferenceCapabilities JSON: {}", e))
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

    async fn branch_context(
        &self,
        req: BranchContextRequest,
    ) -> Result<BranchContextReceipt, InferenceError> {
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
