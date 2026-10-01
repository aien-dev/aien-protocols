# aien-protocols

Versioned specifications and reference crates for AIEN: what portable agent state, inference requests, actions, evaluation and provenance receipts mean. It holds contracts, never private implementations.

## Current state

Research-grade and pre-alpha. The specifications and reference Rust crates (Apache-2.0) in this repository predate the project's decision to target C. The reference crates are legacy: no new Rust is added, and the specifications are the durable part. Language-neutral C implementations will live with their owners (omega, aienos). Status of the whole system is owned by [aien-architecture](https://github.com/aien-dev/aien-architecture): [CURRENT_EXECUTION_PLAN.md](https://github.com/aien-dev/aien-architecture/blob/main/CURRENT_EXECUTION_PLAN.md). No protocol here is claimed as qualified on hardware.

## Layout

```text
specs/       Normative specifications (Community Specification License 1.0):
             agent-state, inference, evaluation
crates/      Reference Rust crates (Apache-2.0), legacy:
             aien-protocol-types, aien-agent-state-abi, aien-inference-protocol,
             aien-inference-client, aien-action-protocol, aien-event-protocol,
             aien-evaluation-protocol, aien-provenance, aien-probe
```

Governance and policy files: [GOVERNANCE.md](GOVERNANCE.md), [SCOPE.md](SCOPE.md), [VERSIONING.md](VERSIONING.md), [CHANGELOG.md](CHANGELOG.md), [CONSUMERS.md](CONSUMERS.md), [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md), [NOTICES.md](NOTICES.md), [TRADEMARKS.md](TRADEMARKS.md).

## Rule of direction

Protocols point inward to nothing. Implementations point downward to protocols. They never point sideways at each other: any deployment needing two implementations in one process is composed from above.

## How this fits with the other repositories

[omega](https://github.com/aien-dev/omega) and [aienos](https://github.com/aien-dev/aienos) implement the contracts in C; [aien-sovereign-core](https://github.com/aien-dev/aien-sovereign-core) is the earlier Rust consumer (legacy); [aien-architecture](https://github.com/aien-dev/aien-architecture) owns status.

## Standing rules

C is the target language, with assembly only where measured; no new Rust; no Python; no CUDA toolkit; no systemd; no outside dependencies in the trusted base.

## Build and test

The legacy reference crates need a Rust toolchain:

```bash
cargo check --workspace --all-targets
cargo test --workspace
```

## Contributing

Open a pull request against `main` with the commands you ran and their output. Specification changes follow [GOVERNANCE.md](GOVERNANCE.md) and [VERSIONING.md](VERSIONING.md). Contact: aien@aienos.com.

## Licensing

Specifications: [Community Specification License 1.0](LICENSE-SPEC). Code and crates: [Apache License 2.0](LICENSE-CODE). Anti-enclosure commitments: [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md).
