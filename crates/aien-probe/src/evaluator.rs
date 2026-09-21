//! Adapter that plugs the probe engine into the unified Evaluator protocol.
//!
//! A [`ProbeEvaluator`] runs a [`ProbeSet`] over the evaluation subject and turns the calibrated
//! answers into an [`EvaluatorOutcome`]. Gates declare which answers must hold for the subject to
//! pass, so a [`ProbeEvaluator`] drops straight into the [`CanaryRollbackHarness`].
//!
//! [`CanaryRollbackHarness`]: aien_evaluation_protocol::CanaryRollbackHarness

use crate::{Answer, ProbeBackend, ProbeEngine, ProbeSet};
use aien_evaluation_protocol::{
    EvaluationError, EvaluationPlan, Evaluator, EvaluatorDescriptor, EvaluatorIdentity,
    EvaluatorOutcome, EvaluatorStatus, Finding, Measurement,
};
use aien_protocol_types::{ArtifactRef, Digest32};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

/// A requirement an answer must satisfy for the subject to pass.
#[derive(Clone, Debug)]
pub enum ProbeGate {
    /// A [`Noul`](crate::Noul) probe whose probability must reach a minimum.
    Noul { id: String, min: f64 },
    /// A [`Score`](crate::Score) probe whose position must reach a minimum.
    Score { id: String, min: f64 },
    /// A [`Choice`](crate::Choice) probe whose selection must be in a set.
    Choice { id: String, allowed: Vec<String> },
}

impl ProbeGate {
    /// A noul gate.
    pub fn noul(id: impl Into<String>, min: f64) -> Self {
        Self::Noul { id: id.into(), min }
    }

    /// A score gate.
    pub fn score(id: impl Into<String>, min: f64) -> Self {
        Self::Score { id: id.into(), min }
    }

    /// A choice gate.
    pub fn choice<I, S>(id: impl Into<String>, allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Choice {
            id: id.into(),
            allowed: allowed.into_iter().map(Into::into).collect(),
        }
    }
}

/// Configuration for a [`ProbeEvaluator`].
#[derive(Clone, Debug, Default)]
pub struct ProbeEvaluatorConfig {
    /// The gates a subject must satisfy.
    pub gates: Vec<ProbeGate>,
}

impl ProbeEvaluatorConfig {
    /// A configuration with no gates.
    pub fn new() -> Self {
        Self { gates: Vec::new() }
    }

    /// Adds a gate.
    pub fn with_gate(mut self, gate: ProbeGate) -> Self {
        self.gates.push(gate);
        self
    }
}

/// An [`Evaluator`] backed by the sovereign probe engine.
pub struct ProbeEvaluator<B: ProbeBackend + 'static> {
    engine: Arc<ProbeEngine<B>>,
    probes: ProbeSet,
    config: ProbeEvaluatorConfig,
    descriptor: EvaluatorDescriptor,
}

impl<B: ProbeBackend + 'static> ProbeEvaluator<B> {
    /// Builds an evaluator over an engine, a probe set, and a gate configuration.
    pub fn new(engine: ProbeEngine<B>, probes: ProbeSet, config: ProbeEvaluatorConfig) -> Self {
        Self {
            engine: Arc::new(engine),
            probes,
            config,
            descriptor: EvaluatorDescriptor {
                evaluator_id: "aien-sovereign-probe".to_string(),
                version: "0.1.0".to_string(),
                required: true,
            },
        }
    }

    /// Overrides the evaluator descriptor.
    pub fn with_descriptor(mut self, descriptor: EvaluatorDescriptor) -> Self {
        self.descriptor = descriptor;
        self
    }

    /// The probe set the evaluator runs.
    pub fn probes(&self) -> &ProbeSet {
        &self.probes
    }
}

#[async_trait]
impl<B: ProbeBackend + 'static> Evaluator for ProbeEvaluator<B> {
    fn descriptor(&self) -> EvaluatorDescriptor {
        self.descriptor.clone()
    }

    async fn evaluate(
        &self,
        plan: &EvaluationPlan,
        subject: &ArtifactRef,
    ) -> Result<EvaluatorOutcome, EvaluationError> {
        let state = json!({
            "evaluation_id": plan.evaluation_id.0.to_string(),
            "profile": plan.profile,
            "sandbox_profile": plan.sandbox_profile,
            "subject": {
                "artifact_id": subject.artifact_id.to_string(),
                "media_type": subject.media_type,
                "byte_size": subject.byte_size,
                "digest": hex::encode(subject.digest.0),
            }
        });

        let response = self
            .engine
            .evaluate(&state, &self.probes)
            .await
            .map_err(|e| EvaluationError::ExecutionFailed(format!("probe engine failure: {e}")))?;

        let mut findings = Vec::new();
        let mut measurements = Vec::new();

        for (id, answer) in &response.answers {
            match answer {
                Answer::Noul(noul) => measurements.push(Measurement {
                    metric: format!("probe_noul_{id}"),
                    value: noul.noul,
                    unit: "ratio".to_string(),
                }),
                Answer::Score(score) => measurements.push(Measurement {
                    metric: format!("probe_score_{id}"),
                    value: score.score,
                    unit: "points".to_string(),
                }),
                Answer::Choice(choice) => measurements.push(Measurement {
                    metric: format!("probe_choice_confidence_{id}"),
                    value: choice.confidence,
                    unit: "ratio".to_string(),
                }),
            }
        }

        for gate in &self.config.gates {
            match gate {
                ProbeGate::Noul { id, min } => {
                    let value = response.noul(id).map(|answer| answer.noul).unwrap_or(0.0);
                    if value < *min {
                        findings.push(Finding {
                            severity: "fatal".to_string(),
                            rule_id: format!("probe:noul:{id}"),
                            message: format!(
                                "noul probe {id} returned {value:.4}, below required {min:.4}"
                            ),
                            location: None,
                        });
                    }
                }
                ProbeGate::Score { id, min } => {
                    let value = response.score(id).map(|answer| answer.score).unwrap_or(0.0);
                    if value < *min {
                        findings.push(Finding {
                            severity: "fatal".to_string(),
                            rule_id: format!("probe:score:{id}"),
                            message: format!(
                                "score probe {id} returned {value:.4}, below required {min:.4}"
                            ),
                            location: None,
                        });
                    }
                }
                ProbeGate::Choice { id, allowed } => {
                    let chosen = response
                        .choice(id)
                        .map(|answer| answer.choice.clone())
                        .unwrap_or_default();
                    if !allowed.contains(&chosen) {
                        findings.push(Finding {
                            severity: "fatal".to_string(),
                            rule_id: format!("probe:choice:{id}"),
                            message: format!(
                                "choice probe {id} selected {chosen}, which is not in the allowed set"
                            ),
                            location: None,
                        });
                    }
                }
            }
        }

        let status = if findings.is_empty() {
            EvaluatorStatus::Passed
        } else {
            EvaluatorStatus::Failed
        };

        let mut outcome = EvaluatorOutcome {
            evaluator: EvaluatorIdentity {
                evaluator_id: self.descriptor.evaluator_id.clone(),
                version: self.descriptor.version.clone(),
                binary_digest: Digest32([0u8; 32]),
                config_digest: Digest32([0u8; 32]),
            },
            status,
            findings,
            measurements,
            evidence: vec![subject.clone()],
            execution_digest: Digest32([0u8; 32]),
        };
        outcome.execution_digest = outcome.compute_execution_digest();

        Ok(outcome)
    }
}
