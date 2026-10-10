# Unified Evaluator Protocol Specification

**Status**: Draft  
**Version**: 1.0.0  
**License**: Community Specification License 1.0  

## Abstract

The Unified Evaluator Protocol establishes the verifier boundary for autonomous candidate evaluation, self-modification, and regression testing.

## Core Concepts

1. **Evaluator SPI**: Independent evaluators (static analysis, regression suites, benchmarks) produce native measurements and findings under a frozen `EvaluationPlan`.
2. **Immutability Invariant**: Candidate Engine N+1 may propose an artifact but may never evaluate itself or modify evaluator rules, thresholds, or verifier keys.
3. **Protected Verifier**: Signed evaluation receipts (`SignedEvaluationReceipt`) are issued exclusively by an isolated verifier identity bound to hardware TPM 2.0 keys.

## Verdict identity domains (registry)

A verdict identity is a lowercase hex SHA-256 over a domain tag, one LF, then lines of exact text joined by LF with no trailing LF. Nothing with a timestamp, host name, path or floating-point value enters it, so two machines that agree on every row produce the same identity. A producer adds its domain here before emitting it; a tag is never reused with a different byte layout.

| domain tag | names | defined in | status |
|---|---|---|---|
| `AIEN_E2E_OBJECTIVE_V1` | the objective identity of the WHOLE-SYSTEM-E2E acceptance test (tag, LF, objective text) | aien-architecture `docs/plans/release-readiness/ACCEPTANCE_E2E.md` section 1 | FROZEN 2026-10-10 |
| `AIEN_E2E_VERDICT_V1` | the verdict identity of the WHOLE-SYSTEM-E2E acceptance test (tag, LF, `objective_id`, `contract_sha256`, rows E1 to E6, CTRL-E1 to CTRL-E6) | same file, section 1, byte layout pinned at freeze | FROZEN 2026-10-10 |

Producers: the harness `scripts/whole_system_e2e.sh` and the verifier `tools/aien-verify` in aien-sovereign-core. The verifier, not the executor, computes the verdict identity (aien-architecture#190, lane L4).
