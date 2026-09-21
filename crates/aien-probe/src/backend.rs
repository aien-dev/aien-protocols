//! Probe backends.
//!
//! A backend turns a state and a probe set into calibrated answers. Two backends ship here: a
//! deterministic in process reference oracle, and an HTTP client for an AIEN inference service.

use crate::math;
use crate::{
    canonicalize, Answer, ChoiceAnswer, NoulAnswer, Probe, ProbeError, ProbeResponse, ProbeSet,
    ScoreAnswer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// A source of calibrated probe answers.
#[async_trait]
pub trait ProbeBackend: Send + Sync {
    /// A human readable name for the backend.
    fn name(&self) -> &str;

    /// Evaluates every probe against the state.
    async fn evaluate(&self, state: &Value, probes: &ProbeSet)
        -> Result<ProbeResponse, ProbeError>;
}

/// A deterministic, in process reference oracle.
///
/// This backend runs no model and opens no socket. It derives a logit for every question from a
/// SHA-256 feature hash of the canonical state and the question label, then applies the same
/// calibration math the device path uses. Given the same state and probes it always returns the
/// same answers, which makes it the conformance oracle for tests and continuous integration.
///
/// It is a reference oracle, not a trained calibrator. For calibrated judgments on real content,
/// point [`HttpProbeBackend`] at an AIEN inference service on the GB10.
pub struct DeterministicReferenceBackend {
    temperature: f64,
}

impl DeterministicReferenceBackend {
    /// A reference oracle at the default temperature of one.
    pub fn new() -> Self {
        Self { temperature: 1.0 }
    }

    /// A reference oracle at a chosen temperature.
    pub fn with_temperature(temperature: f64) -> Self {
        Self { temperature }
    }

    /// The temperature in use.
    pub fn temperature(&self) -> f64 {
        self.temperature
    }

    fn logit(seed: &[u8], label: &[u8], temperature: f64) -> f64 {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update([0u8]);
        hasher.update(label);
        let digest: [u8; 32] = hasher.finalize().into();
        let raw = u64::from_le_bytes(digest[..8].try_into().expect("eight bytes"));
        let unit = (raw as f64) / ((u64::MAX as f64) + 1.0);
        let centered = unit * 2.0 - 1.0;
        math::temperature_scale(centered * 4.0, temperature)
    }

    fn state_seed(state: &Value) -> Result<[u8; 32], ProbeError> {
        let canonical = serde_json::to_vec(&canonicalize(state))
            .map_err(|e| ProbeError::Serialization(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(b"aien-probe-state-v1");
        hasher.update(canonical);
        Ok(hasher.finalize().into())
    }

    fn probe_seed(state_seed: &[u8; 32], id: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(state_seed);
        hasher.update([0u8]);
        hasher.update(id.as_bytes());
        hasher.finalize().into()
    }

    fn answer_noul(&self, seed: &[u8; 32]) -> Answer {
        let z_yes = Self::logit(seed, b"noul:yes", self.temperature);
        let z_no = Self::logit(seed, b"noul:no", self.temperature);
        Answer::Noul(NoulAnswer {
            noul: math::sigmoid(z_yes - z_no),
        })
    }

    fn answer_score(&self, seed: &[u8; 32], criteria: &[String]) -> Answer {
        let logits: Vec<f64> = (0..criteria.len())
            .map(|level| {
                let label = format!("score:{level}");
                Self::logit(seed, label.as_bytes(), self.temperature)
            })
            .collect();
        let probabilities = math::softmax(&logits);
        let score = math::expected_value(&probabilities);
        let confidence = math::confidence(&probabilities);
        let legend = criteria
            .iter()
            .enumerate()
            .map(|(level, criterion)| (level as u32, criterion.clone()))
            .collect();
        let by_level = probabilities
            .iter()
            .enumerate()
            .map(|(level, probability)| (level as u32, *probability))
            .collect();
        Answer::Score(ScoreAnswer {
            score,
            confidence,
            legend,
            probabilities: by_level,
        })
    }

    fn answer_choice(&self, seed: &[u8; 32], options: &[crate::ChoiceOption]) -> Answer {
        let logits: Vec<f64> = options
            .iter()
            .map(|option| {
                let label = format!("choice:{}", option.id);
                Self::logit(seed, label.as_bytes(), self.temperature)
            })
            .collect();
        let probabilities = math::softmax(&logits);
        let confidence = math::confidence(&probabilities);
        let best = probabilities
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(Ordering::Equal))
            .map(|(index, _)| index)
            .unwrap_or(0);
        let choice = options
            .get(best)
            .map(|option| option.id.clone())
            .unwrap_or_default();
        let by_option = options
            .iter()
            .enumerate()
            .map(|(index, option)| (option.id.clone(), probabilities[index]))
            .collect();
        Answer::Choice(ChoiceAnswer {
            choice,
            confidence,
            probabilities: by_option,
        })
    }
}

impl Default for DeterministicReferenceBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProbeBackend for DeterministicReferenceBackend {
    fn name(&self) -> &str {
        "deterministic-reference-oracle"
    }

    async fn evaluate(
        &self,
        state: &Value,
        probes: &ProbeSet,
    ) -> Result<ProbeResponse, ProbeError> {
        let state_seed = Self::state_seed(state)?;
        let mut answers = Vec::with_capacity(probes.len());

        for (id, probe) in probes.iter() {
            let seed = Self::probe_seed(&state_seed, id);
            let answer = match probe {
                Probe::Noul(_) => self.answer_noul(&seed),
                Probe::Score(score) => self.answer_score(&seed, &score.criteria),
                Probe::Choice(choice) => self.answer_choice(&seed, &choice.options),
            };
            answers.push((id.clone(), answer));
        }

        Ok(ProbeResponse {
            model: self.name().to_string(),
            answers,
            latency_micros: 0,
        })
    }
}

/// Wire request for the AIEN probe endpoint.
#[derive(Serialize)]
struct WireRequest<'a> {
    state: &'a Value,
    probes: &'a ProbeSet,
}

/// Wire response from the AIEN probe endpoint.
#[derive(Deserialize)]
struct WireResponse {
    #[serde(default)]
    model: String,
    answers: Vec<(String, Answer)>,
}

/// An HTTP client for an AIEN inference service that taps logits on the device.
///
/// The service exposes `POST <endpoint>/v1/probe` taking `{ "state": ..., "probes": ... }` and
/// returning `{ "model": ..., "answers": [[id, answer], ...] }`. On the GB10 the service prefills
/// the state into the paged KV cache once, forks one copy on write branch per probe, and reads
/// the calibrated distribution from a single forward step.
pub struct HttpProbeBackend {
    client: reqwest::Client,
    endpoint: String,
    model: String,
}

impl HttpProbeBackend {
    /// Builds a backend for an endpoint and model name.
    pub fn with_endpoint(endpoint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            model: model.into(),
        }
    }

    /// Builds a backend for an endpoint with the default model name.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::with_endpoint(endpoint, "aien-sovereign-probe")
    }

    /// Builds a backend from `AIEN_PROBE_ENDPOINT` and `AIEN_PROBE_MODEL`.
    pub fn from_env() -> Result<Self, ProbeError> {
        let endpoint = std::env::var("AIEN_PROBE_ENDPOINT")
            .map_err(|_| ProbeError::Evaluation("AIEN_PROBE_ENDPOINT is not set".to_string()))?;
        let model = std::env::var("AIEN_PROBE_MODEL")
            .unwrap_or_else(|_| "aien-sovereign-probe".to_string());
        Ok(Self::with_endpoint(endpoint, model))
    }

    /// The endpoint in use.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn probe_url(&self) -> String {
        format!("{}/v1/probe", self.endpoint.trim_end_matches('/'))
    }
}

#[async_trait]
impl ProbeBackend for HttpProbeBackend {
    fn name(&self) -> &str {
        "aien-http-probe"
    }

    async fn evaluate(
        &self,
        state: &Value,
        probes: &ProbeSet,
    ) -> Result<ProbeResponse, ProbeError> {
        let body = WireRequest { state, probes };
        let response = self
            .client
            .post(self.probe_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| ProbeError::Transport(e.to_string()))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| ProbeError::Transport(e.to_string()))?;

        if !status.is_success() {
            return Err(ProbeError::Status {
                status: status.as_u16(),
                body: text.chars().take(400).collect(),
            });
        }

        let parsed: WireResponse = serde_json::from_str(&text).map_err(|e| {
            ProbeError::Malformed(format!(
                "{e}; body: {}",
                text.chars().take(200).collect::<String>()
            ))
        })?;

        Ok(ProbeResponse {
            model: if parsed.model.is_empty() {
                self.model.clone()
            } else {
                parsed.model
            },
            answers: parsed.answers,
            latency_micros: 0,
        })
    }
}
