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
