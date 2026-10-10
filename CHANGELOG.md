# Changelog

All notable changes to the versioned specification surface are recorded here.
Reference implementation changes in `crates/` follow the same entries unless
noted. Dates are UTC. Versions follow semantic versioning as defined in
VERSIONING.md.

## [Unreleased]

### Specifications

- `specs/evaluation`: verdict identity domain registry added; `AIEN_E2E_OBJECTIVE_V1` and `AIEN_E2E_VERDICT_V1` registered (FROZEN 2026-10-10 with aien-architecture `ACCEPTANCE_E2E.md`; harness and verifier in aien-sovereign-core produce them).

- `specs/osc-unit-artifact`: OSC Unit Artifact v1 DRAFT, frozen pending ADR reconciliation (2026-10-08), the signed
  container in which an OSC-compiled Omega unit (A64 code plus canonical IR) is
  admitted and launched by AIENOS or the host adapter. Named refusal codes,
  launch result shape, bounded exact-match entry names, instruction-subset code scan, 47 refusal and 5 acceptance container vectors plus lookup, loader-state and launch-argument scenarios, shell generator and
  shell reference checker. No loader implements it yet.
- `specs/crumb-visible`: Crumb Reader Contract 1.0.0 for the CRB1 visible
  record (wire schema 1), numbered refusal codes, check order, determinism
  rule, and a shared conformance corpus (122 family vectors, 5 edge
  positives, 44 refusals) with a shell generator. Extracted from the running
  Rust reference; no new format features.
- `specs/execution-transcript`: TRN1 contract 0.2.0. Adds wire schema 3
  with record types 17 CAUSE, 18 RECEIPT_BIND, 19 RUN_LINK and 21 RESOURCE
  (32-byte cause id); type 20 TRAIN_DISPATCH reserved without a layout.
  Schema 1 files and every 0.1.0 vector keep their outcomes; schema 2 stays
  unassigned. Reference verifier accepts schemas 1 and 3; 0.2 goldens,
  forged histories, 23 refusal vectors and a join expectation list
  (`vectors/join.txt`). Sources: aien-architecture causal-id-join-v0
  (fa46a26) and resource-contract-v0 (ddc17b7).
- `specs/verified-crumb`: Verified Crumb V1 (VC1) contract 0.1.0, new. Canonical
  byte encoding of VerifiedCrumbV1 (big-endian, domain tag
  `AIEN_VERIFIED_CRUMB_V1`, sorted unique lists, no padding), VC id = SHA-256
  of the canonical bytes, resolve rule (lock, semantic id, store, identity,
  receipt, transitive closure, refuse on any failure), 9 resolve refusal codes
  plus 13 format refusal codes and the VC1 addition `VERIFIER_TOO_OLD`, the omega-dev (tainted) and omega-build
  (verified only) domains, and the `omega.lock` text format. Receipt id binds
  to the aien-proof BLAKE3 id. 17 golden vectors (4 accept, 13 refuse), a C
  checker (`tools/vc1-check.c`), and `tools/check-golden.sh` with 3 vector
  mutants and 9 checker mutants. No consumer pins it yet. Open design items
  are listed in SPEC.md sections 4 and 11 (`digest_kind` byte, 0x01 source / 0x02 IR, is part of the encoding).
  Contract 0.2.0 (VC1-RECONCILE): SPEC section 6.2 fixes one meaning per declaration code.
  `UNDECLARED_IMPORT` is only "the program uses something its dependency list
  does not declare" (ARCH-0029 code 7); a lock line, manifest entry or
  `dependencies[]` entry with no import behind it is `UNVERIFIED_DEPENDENCY`;
  an import with no lock line is `DEPENDENCY_NOT_PINNED`. SPEC step 8 now also
  refuses a `dependencies[]` entry the stored source does not import. No byte
  layout, id or golden vector changes. Migration: omega `omega_resolve.c` used
  `UNDECLARED_IMPORT` for a lock line with no import and must move to
  `UNVERIFIED_DEPENDENCY`; aien-closure already agrees.
- `specs/evidence-receipt`: partial extraction of aien-proof EvidenceReceiptV1
  (`SUBSET.md`): only the identity derivation and fields VC1 binds to,
  pinned to aien-sovereign-core `40dd373`. Full extraction is owed.

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
