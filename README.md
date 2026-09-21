# aien-protocols

Canonical specifications, wire protocols, data models, and reference ABI crates for the AIEN ecosystem.

## Architectural Mandate

`aien-protocols` defines what portable AIEN state and wire messages mean. It contains contracts, never private implementations.

```text
                        aien-protocols
                     ┌────────┼────────┐
                     │        │        │
                     ▼        ▼        ▼
              Agent State  Inference  Actions/
                  ABI       Protocol   Provenance
                     ▲        ▲        ▲
                     │        │        │
             ┌───────┘        │        └───────┐
             │                │                │
       aegis-runtime          │      aien-sovereign-core
       (AGPL-3.0-only)        │           (MPL-2.0)
             │                │                │
             └──── NO DIRECT CARGO EDGE ──────┘
```

> **Inward Invariant**: Protocols point inward to nothing. Implementations point downward to protocols. AEGIS and Sovereign Core never point sideways at each other. Any deployment requiring both in one process is composed from above via `aien-local-stack`.

## Repository Structure

```text
aien-protocols/
├── LICENSE-SPEC         Community Specification License 1.0
├── LICENSE-CODE         Apache-2.0
├── ANTI_ENCLOSURE.md    Anti-enclosure commitments and covenants
├── GOVERNANCE.md        Specification development process
├── SCOPE.md             Working group scope definition
├── NOTICES.md           Patent notices and implementer registry
├── TRADEMARKS.md        Conformance and trademark policy
│
├── specs/               Normative specifications (Community-Spec-1.0)
│   ├── agent-state/     Agent State ABI specification
│   ├── inference/       Inference Protocol specification
│   ├── actions/         Action and capability specification
│   ├── evaluation/      Unified Evaluator Protocol specification
│   └── provenance/      Cryptographic attestation and receipt specification
│
├── schemas/             JSON Schemas for language-neutral serialization
│
├── crates/              Reference Rust ABI crates (Apache-2.0)
│   ├── aien-protocol-types
│   ├── aien-agent-state-abi
│   ├── aien-inference-protocol
│   ├── aien-inference-client
│   ├── aien-action-protocol
│   ├── aien-event-protocol
│   ├── aien-evaluation-protocol
│   └── aien-provenance
│
├── bindings/            Cross-language bindings (Mojo, Python, C++)
└── conformance/         Test vectors and validation test suites
```

## Licensing

- **Specifications**: [Community Specification License 1.0](LICENSE-SPEC).
- **Code, Schemas, and Crates**: [Apache License 2.0](LICENSE-CODE).
- **Anti-Enclosure Commitments**: See [ANTI_ENCLOSURE.md](ANTI_ENCLOSURE.md).
