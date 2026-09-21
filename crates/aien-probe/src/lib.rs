//! Sovereign native probe evaluation engine.
//!
//! This crate implements AIEN's native, non-generative evaluation primitive. A caller supplies
//! a JSON state and a set of typed probes. Each probe asks one calibrated question about that
//! state: a yes or no probability ([`Noul`]), a position on an ordered scale ([`Score`]), or one
//! option out of a set ([`Choice`]). Every probe is evaluated against the same state, and the
//! answers come back calibrated.
//!
//! The engine is backend driven:
//!
//! * [`DeterministicReferenceBackend`] runs entirely in process with no network and no model.
//!   It is the offline oracle for conformance tests and continuous integration.
//! * [`HttpProbeBackend`] targets an AIEN inference service that taps logits at a single forward
//!   boundary on the local Grace Blackwell GB10.
//!
//! This is the sovereign path: no external service, no per token fee, and no state leaving the
//! AIEN boundary. The engine plugs into the unified Evaluator protocol through
//! [`ProbeEvaluator`].

pub mod backend;
pub mod evaluator;
pub mod math;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Instant;

pub use backend::{DeterministicReferenceBackend, HttpProbeBackend, ProbeBackend};
pub use evaluator::{ProbeEvaluator, ProbeEvaluatorConfig, ProbeGate};

/// Error type for probe evaluation.
#[derive(thiserror::Error, Debug)]
pub enum ProbeError {
    #[error("probe serialization failed: {0}")]
    Serialization(String),
    #[error("probe backend transport failed: {0}")]
    Transport(String),
    #[error("probe backend returned status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("probe backend returned a malformed response: {0}")]
    Malformed(String),
    #[error("probe evaluation failed: {0}")]
    Evaluation(String),
}

/// A typed question about a JSON state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Probe {
    /// A yes or no question answered by a calibrated probability.
    Noul(Noul),
    /// A judgment on an ordered, described scale.
    Score(Score),
    /// A selection of one option out of a set.
    Choice(Choice),
}

/// A yes or no question.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Noul {
    /// What the question asks.
    pub instructions: String,
    /// An optional description of what a yes means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yes: Option<String>,
    /// An optional description of what a no means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no: Option<String>,
}

impl Noul {
    /// A yes or no question with instructions only.
    pub fn new(instructions: impl Into<String>) -> Self {
        Self {
            instructions: instructions.into(),
            yes: None,
            no: None,
        }
    }

    /// Adds a description of what a yes means.
    pub fn with_yes(mut self, yes: impl Into<String>) -> Self {
        self.yes = Some(yes.into());
        self
    }

    /// Adds a description of what a no means.
    pub fn with_no(mut self, no: impl Into<String>) -> Self {
        self.no = Some(no.into());
        self
    }
}

/// A judgment on an ordered scale, one criterion per level.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// What the question asks.
    pub instructions: String,
    /// The levels of the scale in order, lowest first.
    pub criteria: Vec<String>,
}

impl Score {
    /// A score question with an ordered list of criteria.
    pub fn new<I, S>(instructions: impl Into<String>, criteria: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            instructions: instructions.into(),
            criteria: criteria.into_iter().map(Into::into).collect(),
        }
    }
}

/// A selection of one option out of a set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Choice {
    /// What the question asks.
    pub instructions: String,
    /// The options to choose from.
    pub options: Vec<ChoiceOption>,
}

impl Choice {
    /// A choice question over a list of options.
    pub fn new<I>(instructions: impl Into<String>, options: I) -> Self
    where
        I: IntoIterator<Item = ChoiceOption>,
    {
        Self {
            instructions: instructions.into(),
            options: options.into_iter().collect(),
        }
    }
}

/// One option of a choice question.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChoiceOption {
    /// The stable identifier of the option.
    pub id: String,
    /// An optional description of the option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ChoiceOption {
    /// An option with an identifier only.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: None,
        }
    }

    /// Adds a description to the option.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// The answer to one probe, of the type the probe had.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    /// The answer to a [`Noul`].
    Noul(NoulAnswer),
    /// The answer to a [`Score`].
    Score(ScoreAnswer),
    /// The answer to a [`Choice`].
    Choice(ChoiceAnswer),
}

/// The answer to a yes or no question.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NoulAnswer {
    /// The calibrated probability that the answer is yes, from zero to one.
    pub noul: f64,
}

/// The answer to a score question.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ScoreAnswer {
    /// The probability weighted position on the scale.
    pub score: f64,
    /// How concentrated the distribution is, from zero to one.
    pub confidence: f64,
    /// Each level and the criterion the question gave it.
    pub legend: BTreeMap<u32, String>,
    /// Each level and its probability.
    pub probabilities: BTreeMap<u32, f64>,
}

impl<'de> Deserialize<'de> for ScoreAnswer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            score: f64,
            confidence: f64,
            legend: BTreeMap<String, String>,
            probabilities: BTreeMap<String, f64>,
        }

        fn by_level<T, E>(map: BTreeMap<String, T>, field: &str) -> Result<BTreeMap<u32, T>, E>
        where
            E: serde::de::Error,
        {
            map.into_iter()
                .map(|(level, value)| match level.parse::<u32>() {
                    Ok(level) => Ok((level, value)),
                    Err(_) => Err(E::custom(format!(
                        "{field} has the key {level}, which is not a level number"
                    ))),
                })
                .collect()
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(ScoreAnswer {
            score: raw.score,
            confidence: raw.confidence,
            legend: by_level(raw.legend, "legend")?,
            probabilities: by_level(raw.probabilities, "probabilities")?,
        })
    }
}

/// The answer to a choice question.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChoiceAnswer {
    /// The option with the highest probability.
    pub choice: String,
    /// How concentrated the distribution is, from zero to one.
    pub confidence: f64,
    /// Every option and its probability.
    pub probabilities: BTreeMap<String, f64>,
}

/// An ordered set of probes keyed by identifier.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProbeSet {
    entries: Vec<(String, Probe)>,
}

impl ProbeSet {
    /// An empty probe set.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a probe under an identifier, in builder style.
    pub fn with(mut self, id: impl Into<String>, probe: Probe) -> Self {
        self.entries.push((id.into(), probe));
        self
    }

    /// Adds a probe under an identifier.
    pub fn insert(&mut self, id: impl Into<String>, probe: Probe) {
        self.entries.push((id.into(), probe));
    }

    /// The probe under an identifier.
    pub fn get(&self, id: &str) -> Option<&Probe> {
        self.entries
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, probe)| probe)
    }

    /// The number of probes.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over the probes in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Probe)> {
        self.entries.iter().map(|(key, probe)| (key, probe))
    }
}

/// The answers to one probe request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeResponse {
    /// The model or backend that produced the answers.
    pub model: String,
    /// One answer per probe, in request order.
    pub answers: Vec<(String, Answer)>,
    /// Wall clock time the evaluation took, in microseconds.
    #[serde(default)]
    pub latency_micros: u64,
}

impl ProbeResponse {
    /// The answer under an identifier.
    pub fn answer(&self, id: &str) -> Option<&Answer> {
        self.answers
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, answer)| answer)
    }

    /// The answer under an identifier, if it answers a [`Noul`].
    pub fn noul(&self, id: &str) -> Option<&NoulAnswer> {
        match self.answer(id)? {
            Answer::Noul(answer) => Some(answer),
            _ => None,
        }
    }

    /// The answer under an identifier, if it answers a [`Score`].
    pub fn score(&self, id: &str) -> Option<&ScoreAnswer> {
        match self.answer(id)? {
            Answer::Score(answer) => Some(answer),
            _ => None,
        }
    }

    /// The answer under an identifier, if it answers a [`Choice`].
    pub fn choice(&self, id: &str) -> Option<&ChoiceAnswer> {
        match self.answer(id)? {
            Answer::Choice(answer) => Some(answer),
            _ => None,
        }
    }
}

/// Runs a [`ProbeBackend`] over a state and a probe set.
pub struct ProbeEngine<B: ProbeBackend> {
    backend: B,
}

impl<B: ProbeBackend> ProbeEngine<B> {
    /// Builds an engine over a backend.
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// The backend the engine runs.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Evaluates every probe against the state and returns the calibrated answers.
    pub async fn evaluate(
        &self,
        state: &Value,
        probes: &ProbeSet,
    ) -> Result<ProbeResponse, ProbeError> {
        let started = Instant::now();
        let mut response = self.backend.evaluate(state, probes).await?;
        response.latency_micros = started.elapsed().as_micros() as u64;
        Ok(response)
    }
}

/// Recursively orders object keys so the serialized form of a state is byte stable.
pub(crate) fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}
