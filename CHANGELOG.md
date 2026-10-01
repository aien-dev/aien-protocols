# Changelog

All notable changes to the versioned specification surface are recorded here.
Reference implementation changes in `crates/` follow the same entries unless
noted. Dates are UTC. Versions follow semantic versioning as defined in
VERSIONING.md.

## [Unreleased]

### Specifications

- `specs/crumb-visible`: Crumb Reader Contract 1.0.0 for the CRB1 visible
  record (wire schema 1), numbered refusal codes, check order, determinism
  rule, and a shared conformance corpus (122 family vectors, 5 edge
  positives, 44 refusals) with a shell generator. Extracted from the running
  Rust reference; no new format features.

## [v0.1.0] - 2026-09-23

First versioned snapshot. No compatibility commitments predate this tag.

### Specifications

- Agent state, evaluation, and inference specs as present in `specs/`.
- Community Specification License 1.0 (`LICENSE-SPEC`).

### Reference crates

- Nine crates at `0.1.0`: protocol types, action protocol, agent state ABI,
  evaluation protocol, event protocol, inference client, inference protocol,
  probe, provenance. Apache-2.0 (`LICENSE-CODE`).

### Known consumers at this tag

Recorded in CONSUMERS.md. Consumers pin this version until a newer tag and
migration notes exist.
