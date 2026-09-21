use aien_evaluation_protocol::{
    CanaryRollbackHarness, EvaluationPlan, Evaluator, EvaluatorStatus, SoftwareP256Signer, Verdict,
    VerifierIdentity, VerifierSigner,
};
use aien_probe::{
    Choice, ChoiceOption, DeterministicReferenceBackend, HttpProbeBackend, Noul, Probe,
    ProbeBackend, ProbeEngine, ProbeEvaluator, ProbeEvaluatorConfig, ProbeGate, ProbeSet, Score,
};
use aien_protocol_types::{ArtifactRef, Digest32, EvaluationId, Timestamp};
use p256::ecdsa::SigningKey;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn sample_state() -> serde_json::Value {
    json!({
        "diff": "fn add(a: i32, b: i32) -> i32 { a + b }",
        "author": "contributor",
        "files": ["src/lib.rs"],
    })
}

fn sample_probes() -> ProbeSet {
    ProbeSet::new()
        .with(
            "telemetry",
            Probe::Noul(Noul::new(
                "Does this patch introduce covert network telemetry?",
            )),
        )
        .with(
            "quality",
            Probe::Score(Score::new(
                "Rate the architectural quality.",
                ["unacceptable", "needs_rework", "acceptable", "exemplary"],
            )),
        )
        .with(
            "severity",
            Probe::Choice(Choice::new(
                "Classify the finding.",
                [
                    ChoiceOption::new("clean").with_description("No issue"),
                    ChoiceOption::new("advisory").with_description("Minor note"),
                    ChoiceOption::new("critical").with_description("Blocks merge"),
                ],
            )),
        )
}

#[tokio::test]
async fn test_deterministic_backend_is_reproducible() {
    let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
    let probes = sample_probes();

    let first = engine.evaluate(&sample_state(), &probes).await.unwrap();
    let second = engine.evaluate(&sample_state(), &probes).await.unwrap();

    assert_eq!(first.answers, second.answers);
    assert_eq!(first.model, "deterministic-reference-oracle");
    assert_eq!(first.answers.len(), 3);
}

#[tokio::test]
async fn test_deterministic_backend_varies_with_state() {
    let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
    let probes = sample_probes();

    let a = engine
        .evaluate(&json!({"diff": "alpha"}), &probes)
        .await
        .unwrap();
    let b = engine
        .evaluate(&json!({"diff": "omega"}), &probes)
        .await
        .unwrap();

    let a_noul = a.noul("telemetry").unwrap().noul;
    let b_noul = b.noul("telemetry").unwrap().noul;
    assert!((a_noul - b_noul).abs() > 1.0e-6);
}

#[tokio::test]
async fn test_answer_ranges_and_distributions() {
    let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
    let probes = sample_probes();
    let response = engine.evaluate(&sample_state(), &probes).await.unwrap();

    let noul = response.noul("telemetry").unwrap().noul;
    assert!((0.0..=1.0).contains(&noul));

    let score = response.score("quality").unwrap();
    let sum: f64 = score.probabilities.values().sum();
    assert!((sum - 1.0).abs() < 1.0e-9);
    assert_eq!(score.legend.len(), 4);
    let weighted: f64 = score
        .probabilities
        .iter()
        .map(|(level, probability)| *level as f64 * probability)
        .sum();
    assert!((weighted - score.score).abs() < 1.0e-9);
    assert!((0.0..=1.0).contains(&score.confidence));

    let choice = response.choice("severity").unwrap();
    let best = choice
        .probabilities
        .iter()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .map(|(id, _)| id.clone())
        .unwrap();
    assert_eq!(choice.choice, best);
}

#[tokio::test]
async fn test_probe_evaluator_gates_pass() {
    let backend = DeterministicReferenceBackend::new();
    let config = ProbeEvaluatorConfig::new();
    let evaluator = ProbeEvaluator::new(ProbeEngine::new(backend), sample_probes(), config);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([1u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 4096,
    };
    let plan = build_plan(&evaluator, subject.clone());

    let outcome = evaluator.evaluate(&plan, &subject).await.unwrap();
    assert_eq!(outcome.status, EvaluatorStatus::Passed);
    assert!(outcome.findings.is_empty());
    assert_eq!(outcome.measurements.len(), 3);
    assert_ne!(outcome.execution_digest, Digest32([0u8; 32]));
}

#[tokio::test]
async fn test_probe_evaluator_gate_fails_closed() {
    let backend = DeterministicReferenceBackend::new();
    let config = ProbeEvaluatorConfig::new()
        .with_gate(ProbeGate::noul("telemetry", 0.999999))
        .with_gate(ProbeGate::score("quality", 3.999999))
        .with_gate(ProbeGate::choice("severity", ["clean"]));
    let evaluator = ProbeEvaluator::new(ProbeEngine::new(backend), sample_probes(), config);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([2u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 2048,
    };
    let plan = build_plan(&evaluator, subject.clone());

    let outcome = evaluator.evaluate(&plan, &subject).await.unwrap();
    assert_eq!(outcome.status, EvaluatorStatus::Failed);
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.rule_id == "probe:noul:telemetry"));
    assert!(outcome
        .findings
        .iter()
        .any(|f| f.rule_id == "probe:score:quality"));
}

#[tokio::test]
async fn test_probe_evaluator_plugs_into_canary_harness() {
    let backend = DeterministicReferenceBackend::new();
    let evaluator = ProbeEvaluator::new(
        ProbeEngine::new(backend),
        sample_probes(),
        ProbeEvaluatorConfig::new(),
    );
    let descriptor = evaluator.descriptor();

    let signing_key = SigningKey::from_slice(&[42u8; 32]).unwrap();
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let verifier = VerifierIdentity {
        principal_id: "canary-daemon".to_string(),
        key_id: signer.key_fingerprint(),
        trust_epoch: 1,
        trusted_build_digest: Digest32([10u8; 32]),
        policy_bundle_digest: Digest32([11u8; 32]),
    };
    let harness = CanaryRollbackHarness::new(verifier, signer);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([12u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 8192,
    };
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId(uuid::Uuid::new_v4()),
        subject: subject.clone(),
        profile: "canary".to_string(),
        evaluators: vec![descriptor],
        baseline: None,
        sandbox_profile: "default".to_string(),
        policy_digest: Digest32([13u8; 32]),
        evaluator_manifest_digest: Digest32([14u8; 32]),
        plan_digest: Digest32([0u8; 32]),
    };
    plan.plan_digest = plan.compute_plan_digest();

    let rollback = Arc::new(AtomicBool::new(false));
    let rollback_flag = rollback.clone();
    let evaluators: Vec<Box<dyn Evaluator>> = vec![Box::new(evaluator)];

    let (receipt, outcomes) = harness
        .evaluate_and_enforce(
            &plan,
            &subject,
            &evaluators,
            Timestamp(1000),
            || async move {
                rollback_flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();

    assert_eq!(receipt.receipt.verdict, Verdict::Pass);
    assert_eq!(outcomes[0].status, EvaluatorStatus::Passed);
    assert!(!rollback.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_probe_evaluator_triggers_rollback_on_gate_failure() {
    let backend = DeterministicReferenceBackend::new();
    let evaluator = ProbeEvaluator::new(
        ProbeEngine::new(backend),
        sample_probes(),
        ProbeEvaluatorConfig::new().with_gate(ProbeGate::noul("telemetry", 0.999999)),
    );
    let descriptor = evaluator.descriptor();

    let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let signer = Arc::new(SoftwareP256Signer::new(signing_key));
    let verifier = VerifierIdentity {
        principal_id: "canary-daemon".to_string(),
        key_id: signer.key_fingerprint(),
        trust_epoch: 1,
        trusted_build_digest: Digest32([20u8; 32]),
        policy_bundle_digest: Digest32([21u8; 32]),
    };
    let harness = CanaryRollbackHarness::new(verifier, signer);

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([22u8; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 512,
    };
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId(uuid::Uuid::new_v4()),
        subject: subject.clone(),
        profile: "canary".to_string(),
        evaluators: vec![descriptor],
        baseline: None,
        sandbox_profile: "default".to_string(),
        policy_digest: Digest32([23u8; 32]),
        evaluator_manifest_digest: Digest32([24u8; 32]),
        plan_digest: Digest32([0u8; 32]),
    };
    plan.plan_digest = plan.compute_plan_digest();

    let rollback = Arc::new(AtomicBool::new(false));
    let rollback_flag = rollback.clone();
    let evaluators: Vec<Box<dyn Evaluator>> = vec![Box::new(evaluator)];

    let (receipt, outcomes) = harness
        .evaluate_and_enforce(
            &plan,
            &subject,
            &evaluators,
            Timestamp(2000),
            || async move {
                rollback_flag.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();

    assert_eq!(receipt.receipt.verdict, Verdict::Fail);
    assert_eq!(outcomes[0].status, EvaluatorStatus::Failed);
    assert!(rollback.load(Ordering::SeqCst));
}

#[tokio::test]
async fn test_http_backend_wire_lifecycle() {
    let body = json!({
        "model": "atlas-lightning-omni",
        "answers": [
            ["telemetry", {"type": "noul", "noul": 0.02}],
            ["quality", {
                "type": "score",
                "score": 3.1,
                "confidence": 0.9,
                "legend": {"0": "unacceptable", "1": "needs_rework", "2": "acceptable", "3": "exemplary"},
                "probabilities": {"0": 0.0, "1": 0.02, "2": 0.08, "3": 0.9}
            }]
        ]
    })
    .to_string();

    let endpoint = spawn_mock_probe_server(body).await;
    let backend = HttpProbeBackend::with_endpoint(endpoint, "atlas-lightning-omni");
    let probes = ProbeSet::new()
        .with("telemetry", Probe::Noul(Noul::new("telemetry?")))
        .with(
            "quality",
            Probe::Score(Score::new("quality?", ["a", "b", "c", "d"])),
        );

    let response = backend.evaluate(&sample_state(), &probes).await.unwrap();
    assert_eq!(response.model, "atlas-lightning-omni");
    assert!((response.noul("telemetry").unwrap().noul - 0.02).abs() < 1.0e-9);
    assert!((response.score("quality").unwrap().score - 3.1).abs() < 1.0e-9);
}

fn build_plan<E: Evaluator>(evaluator: &E, subject: ArtifactRef) -> EvaluationPlan {
    let mut plan = EvaluationPlan {
        evaluation_id: EvaluationId(uuid::Uuid::new_v4()),
        subject,
        profile: "sovereign-audit".to_string(),
        evaluators: vec![evaluator.descriptor()],
        baseline: None,
        sandbox_profile: "isolated".to_string(),
        policy_digest: Digest32([2u8; 32]),
        evaluator_manifest_digest: Digest32([3u8; 32]),
        plan_digest: Digest32([0u8; 32]),
    };
    plan.plan_digest = plan.compute_plan_digest();
    plan
}

async fn spawn_mock_probe_server(body: String) -> String {
    use axum::{routing::post, Router};

    let app = Router::new().route(
        "/v1/probe",
        post(move || {
            let body = body.clone();
            async move { body }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{}", addr)
}
