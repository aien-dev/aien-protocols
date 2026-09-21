# aien-probe

Sovereign native probe evaluation engine for the AIEN platform.

## What it is

`aien-probe` implements a non-generative evaluation primitive. A caller supplies a JSON state and
a set of typed probes. Each probe asks one calibrated question about that state:

- `Noul`: a yes or no question, answered by a calibrated probability.
- `Score`: a judgment on an ordered, described scale.
- `Choice`: a selection of one option out of a set.

Every probe is evaluated against the same state. The answers come back calibrated, and the engine
is backend driven.

## Why it exists

This is the sovereign path. The engine runs inside the AIEN boundary with no external service, no
per token fee, and no state leaving the platform. It is AIEN's native implementation of the
calibrated probe idea, built to run on the local Grace Blackwell GB10 through the AIEN inference
service.

## Backends

| Backend | Network | Model | Use |
| --- | --- | --- | --- |
| `DeterministicReferenceBackend` | No | No | Offline conformance oracle for tests and continuous integration |
| `HttpProbeBackend` | Yes | GB10 service | Calibrated judgments on real content |

`DeterministicReferenceBackend` derives a logit for every question from a SHA-256 feature hash of
the canonical state and the question label, then applies the same calibration math the device path
uses. Given the same state and probes it always returns the same answers. It is a reference oracle,
not a trained calibrator.

`HttpProbeBackend` posts to `POST <endpoint>/v1/probe` and reads the calibrated answers back. On the
GB10 the service prefills the state into the paged KV cache once, forks one copy on write branch per
probe, and reads the distribution from a single forward step.

## Usage

```rust
use aien_probe::{
    Noul, Probe, ProbeEngine, ProbeSet, Score, DeterministicReferenceBackend,
};
use serde_json::json;

let engine = ProbeEngine::new(DeterministicReferenceBackend::new());
let probes = ProbeSet::new()
    .with("telemetry", Probe::Noul(Noul::new("Does this patch add network telemetry?")))
    .with("quality", Probe::Score(Score::new(
        "Rate the architectural quality.",
        ["unacceptable", "needs_rework", "acceptable", "exemplary"],
    )));

let response = engine.evaluate(&json!({"diff": "..."}), &probes).await?;
println!("telemetry probability {:.4}", response.noul("telemetry").unwrap().noul);
println!("quality score {:.2}", response.score("quality").unwrap().score);
```

## Evaluator protocol

`ProbeEvaluator` implements the unified `Evaluator` trait from `aien-evaluation-protocol`, so a
probe set with gates drops straight into the `CanaryRollbackHarness`. Gates declare which answers
must hold for a subject to pass. A violated gate becomes a fatal finding and, in the harness,
triggers rollback.

## License

Apache-2.0.
