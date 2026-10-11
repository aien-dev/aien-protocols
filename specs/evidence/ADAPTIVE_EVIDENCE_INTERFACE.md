# Adaptive Evidence Interface (AEI1)

**Status**: Draft for freeze, 2026-10-11 (AIEN Adaptive Intelligence, Milestone 7 prerequisite). Requirements only: no code in this cut.
**Contract version**: 0.1.0 (major zero, see VERSIONING.md)
**License**: Community Specification License 1.0
**Authority**: the Rust and C source named below, as pinned in section 8. Where this file and that source differ, the source wins and this file is wrong. Anything not found in source is marked **OPEN** and is a question, not a decision.
**Evidence**: `adaptive/INVENTORY.md` and `adaptive/inventory/evidence-chain.md` (Milestone 0, 2026-10-11). Paths: `aien-protocols` = this repo at `407487b7e163`; `interplane` `667fbe811f78`; `spark-rsi` `24f412f699f1`; `omega` `16e729b6d844`.

## 1. Purpose and the one rule

Today four receipt formats exist and none binds a candidate to the run that tested it:

| Format | Where | Binds candidate | Binds run / transcript | Signed |
|---|---|---|---|---|
| `SignedEvaluationReceipt` | aien-protocols `crates/aien-evaluation-protocol/src/lib.rs:583` | `subject_digest` :514 | no | yes, P-256 |
| `rsi-eval/2` judge receipt | interplane `provenance/src/evaluation.rs:96-175` | `candidate_id`, `subject_sha256` | no | yes, P-256 |
| `EvidenceReceiptV1` | specs/evidence-receipt/SUBSET.md (partial); source in aien-sovereign-core `aien-proof` | no (artifact lists) | no | tier field, no signature found here |
| prime-race receipt v1 | benchmarks `prime-drag-race/src/receipt.rs:20-40` | no | no | no |

**Rule A1 (no fourth format).** The adaptive program produces exactly ONE evidence receipt, defined in section 2 as an extension of the aien-protocols evaluation receipt. No new receipt struct, schema string or signing scheme may be introduced. Existing formats are either adapted into the one receipt (OPEN Q2) or stay what they are and are never presented as adaptive evidence. A reviewer must refuse a PR that adds a fourth.

## 2. The one signed evidence receipt (AEI1 receipt)

### 2.1 Base type and what is added

Base: `SignedEvaluationReceipt` (`aien-evaluation-protocol/src/lib.rs:583-589`: `receipt`, `signature`, `cryptographic_tier`, `key_fingerprint`) wrapping `EvaluationReceipt` (:510-522). Chosen because it is the only existing format that has a pluggable hardware-capable signer (`VerifierSigner` :254, `SoftwareP256Signer` :262, `TpmP256Signer` :300), a plan-digest/policy binding, and a verifier identity (`VerifierIdentity` :222-228).

Fields reused unchanged from `EvaluationReceipt` (:510-522), all already in `compute_receipt_digest` (:525-555):

| Requirement | Existing field | Type |
|---|---|---|
| evaluation verdict | `verdict` | `Verdict {Pass, Fail, Indeterminate}` (:215-219) |
| candidate digest | `subject_digest` | `Digest32` (aien-protocol-types `lib.rs:27`, 32 bytes) |
| producer identity | `verifier: VerifierIdentity` = `principal_id`, `key_id`, `trust_epoch`, `trusted_build_digest`, `policy_bundle_digest` | String, String, u64, Digest32, Digest32 |
| timestamps | `started_at`, `completed_at` | `Timestamp(u64)` microseconds (protocol-types `lib.rs:178-188`) |
| evaluation identity | `evaluation_id`, `request_digest`, `plan_digest`, `evidence_root`, `outcomes_root`, `protocol_version` | as in :511-517 |

Fields ADDED (not present today; grep of the crate finds no world, generation or execution-id field, evidence-chain.md sec. 1). All added fields MUST enter `compute_receipt_digest`, appended after `completed_at`, and `protocol_version` MUST be bumped so an old verifier refuses rather than ignores them:

| New field | Type | Source in existing code | Notes |
|---|---|---|---|
| `world_id` | `Digest32` | none found in omega or protocols | **OPEN Q1**: no world identity type exists (omega `RxWorld` has no stable id field that I verified). Until defined, receipts cannot claim a world. |
| `generation` | `u64` | `CxHeader.generation` (omega `src/runtime/rx_cortex.h:121`, header struct :154-160) and `RxLivingProvenance.epoch` (`rx_living.h:90`) | The generation the candidate was promoted or evaluated under. OPEN Q3: which of the two counters. |
| `execution_id` | `[u8;32]` | TRN1 header `run_id`, bytes 8-40 (TRN1_TRANSCRIPT_SPEC.md:59, "opaque; the root causal id") | Equals the transcript's `run_id`. Joins receipt to transcript. |
| `transcript_digest` | `Digest32` | TRN1 **final digest**: record digest of the `END` record (TRN1_TRANSCRIPT_SPEC.md:89-91) | "publishing it in a receipt pins the whole file". |
| `cortex_chain_head` | `Digest32` | `CxStore.chain[32]`, "running hash over every digest in append order" (omega `rx_cortex.h:143`) | Head at the moment the receipt is issued, after the last evidence record. |
| `producer_subsystem` | `u16` | TRN1 header `producer` (TRN1_TRANSCRIPT_SPEC.md:60, offset 40, "subsystem id, not 0") | Names the runtime that wrote the transcript. Distinct from `verifier`. |
| `proposer` | `String` | `EvaluationRequest.proposer` (lib.rs:20) | Copied into the receipt so self-approval (section 6, N8) is checkable from the receipt alone. |
| `evidence_class` | enum `{Production, Fixture}` | section 5; mirrors `ObservationProvenance {Measured, Synthetic}` (spark-rsi `src/canary_observation.rs:11-15`) | Type-level, in the digest. |

`candidate digest` is `subject_digest` and nothing else; no second candidate field.

### 2.2 Verification requirements (frozen)

A consumer MUST, in this order, and refuse with a distinct code at the first failure:
1. Recompute the receipt digest and verify the P-256 signature (`SignedEvaluationReceipt::verify`, lib.rs:591-601) against a key the **operator** supplies, never one carried in the receipt (same rule as interplane `evaluation.rs:1-8`).
2. Check that `cryptographic_tier` and `key_fingerprint` match the trusted key. Today `verify` ignores both (lib.rs:591-601; evidence-chain.md sec. 7 gap 4). **This is a defect to fix before AEI1 is usable**, not a design choice.
3. Check `verifier.key_id == key_fingerprint` (already enforced at signing, lib.rs:562, must also be enforced at verify).
4. Check `subject_digest` equals the digest of the candidate bytes the consumer is about to admit.
5. Check `execution_id` and `transcript_digest` against a TRN1 transcript that passes the reference verifier (`tools/trn1_verify.c`): header `run_id` equal, `END` record digest equal.
6. Check `cortex_chain_head` is reachable in the Cortex journal being relied upon (OPEN Q4: how a consumer proves reachability; omega has `cx_verify` per INVENTORY row 4 but I did not read its contract here).
7. Check `evidence_class == Production` unless the consumer is a fixture runner (section 5).
8. Check `proposer != verifier.principal_id` and the self-approval rule (section 6, N8).

## 3. TRN1 transcript production requirement

Facts: TRN1 status is "Not yet produced by any runtime" (TRN1_TRANSCRIPT_SPEC.md:3). Planned producers: omega `tools/replay` and sovereign-core `crates/aien-replay` (:9). The spec states "No signature over the final digest. Anchoring the final digest in a signed receipt belongs to the receipt format, not to TRN1" (:473-475). A rewrite that renumbers and rechains verifies (corpus `f001`, :389-392).

Requirements (frozen):
- **T1 Producer.** For every adaptive evaluation run, the runtime that executed the candidate (omega living body, or the sovereign-core compose run) MUST emit one TRN1 transcript, schema 3, with `producer` set to its subsystem id (section 5.2 of the TRN1 spec). The evaluator MUST NOT be that same process's candidate code path (it may share the binary but the transcript writer is outside the candidate's authority; OPEN Q5: how that separation is enforced in omega).
- **T2 Where signed.** The transcript file itself stays unsigned. Its `END` record digest is signed **only** by being the `transcript_digest` field of the AEI1 receipt (section 2.1), signed by the verifier key. No second signature scheme.
- **T3 Order.** The transcript is complete and closed (`END` present) before the receipt is signed. A receipt over a transcript without `END`, or whose verifier output is `refuse`, MUST be `Indeterminate` or `Fail`, never `Pass`.
- **T4 Join.** `execution_id` (= `run_id`) is the only join key. The causal join rules in the TRN1 spec (:470) are join rules, not verifier rules; AEI1 consumers MUST apply them in their own code and test them (matrix N3).
- **T5 Corpus.** The producer MUST pass `tools/check-corpus.sh` and `tools/mutate-verifier.sh` (survivor count 0, `mutate-verifier.sh:30`) against its output reader before its first receipt is accepted.
- Status: nothing in this section is implemented. This document does not choose the writer implementation (OPEN Q5).

## 4. Measured execution observation (RSI, Milestone 5)

Reuse `CanaryObservation` (spark-rsi `src/canary_observation.rs:17-25`) and its `canonical_bytes` (:34-49: one JSON object, keys alphabetical, no whitespace) and `digest_hex` (SHA-256 of canonical bytes, :51-53). Today it has no signature and no source identity; the daemon feeds `&[]` (spark-rsi `src/daemon.rs:445-446`) so the production gate fails closed by design.

| Field | Status | Type / rule |
|---|---|---|
| `observation_id` | existing :19 | `String`, non-empty (checked in `admit_production_quota`) |
| `candidate_digest` | existing :21 | `String` (lowercase hex SHA-256). MUST equal the AEI1 `subject_digest` hex. |
| `observed_at_ms` | existing :20 | `u64` ms. OPEN Q6: AEI1 `Timestamp` is microseconds; unit conversion rule must be fixed. |
| `status` | existing :23 | `String`, non-empty. OPEN Q7: closed vocabulary needed; reuse `EvaluatorStatus` names (lib.rs:142-147: Passed, Failed, Inconclusive, TimedOut)? |
| `latency_us` | existing :22 | `u64` |
| `provenance` | existing :11-15 | `Measured` / `Synthetic` (see O4) |
| `execution_id` | ADDED | `[u8;32]`, the TRN1 `run_id` of the run that was observed |
| `source_id` | ADDED | String: producer principal; MUST match a key in the operator's trusted-source list |
| `source_signature` | ADDED | P-256 signature by that source over `digest_hex` bytes (same scheme as `SignedEvaluationReceipt`: `VerifierSigner` lib.rs:254) |
| `resource_costs` | ADDED | list of (metric String, value). Reuse `Measurement` (lib.rs:158) as the element type. OPEN Q8: which metrics are required beyond `latency_us`. |

Rules (frozen):
- **O1 Dedupe.** Same `observation_id` + same canonical record = idempotent, counted once. Same id + different record = conflict, the whole batch is refused. This is the existing behaviour (spark-rsi `canary_observation.rs:1-6`, `admit_production_quota` loop) and MUST be preserved.
- **O2 Replay.** An observation whose `execution_id` was already consumed for a different `candidate_digest` is refused. An observation older than the candidate's `started_at` or newer than the receipt's `completed_at` is refused (OPEN Q9: window policy).
- **O3 Signature.** An unsigned observation, or one whose `source_id` is not trusted, MUST NOT be counted toward any production quota. (Today none are signed; this is the missing authenticated feed, INVENTORY row 14, gap G6.)
- **O4 Synthetic marker.** `provenance: Synthetic` observations may have the same shape but the production gate MUST refuse them, as `admit_production_quota` does at :76-79 ("synthetic rehearsal cannot satisfy the production canary quota"). The marker is part of the signed canonical bytes. A `Synthetic` value MUST NOT be settable by a code path that also signs with a production source key (OPEN Q10: enforced how).
- **O5 Source.** The only candidate source named by the inventory is the sovereign-core executor emitting `CanaryObservation` (INVENTORY gap G6). It does not do so today. Nothing here claims it does.

## 5. Benchmark fixture versus production observation

Problem: benchmark receipts today are unsigned and use their own schema (`aien-prime-race/receipt/v1`, benchmarks `prime-drag-race/src/lib.rs:15`); developer fixtures and real runs share a shape.

Requirements (frozen):
- **B1 Type-level split.** Two distinct types, not one type with a flag a consumer can forget: `ProductionObservation` and `FixtureObservation`. Only `ProductionObservation` is accepted by any admit/promote/gate function; `FixtureObservation` has no conversion into it (no `From`, no `Into`, no shared trait that the gate accepts). A fixture can be read by a fixture runner only.
- **B2 Serialized marker.** The serialized form carries `evidence_class` (section 2.1) inside the signed bytes, so stripping or flipping it breaks the signature. Value space is closed; unknown value = refuse.
- **B3 Key separation.** Fixture signing keys MUST NOT chain to the production trust root. A production consumer pins only production keys, so a fixture signed with a fixture key fails step 1 of section 2.2.
- **B4 Naming.** Fixture files live under a path containing `fixtures/` and a filename suffix `.fixture.json`; a production loader MUST refuse any path matching either. (Convention only; the type split in B1 is the real guard.)
- **B5 Existing code.** The benchmarks main crate does not build from a fresh clone (benchmarks `Cargo.toml:18-22`, missing sibling) and has no tamper tests; it is not production evidence today. The prime-race receipt is content-addressed and no-overwrite (receipt.rs:20-40) but unsigned: it is a `Fixture` class until adapted (OPEN Q2).
- **B6 Time series.** A longitudinal history store does not exist (evidence-chain.md sec. 7, gap 5). Milestone 7 owns it; this spec only requires that every row in it is an AEI1 receipt or a `FixtureObservation`, never mixed.

## 6. Negative-test matrix (the implementation MUST pass all)

Each row: a bad artifact goes in; a named refusal comes out; no `Pass`. "Existing" lists a nearest test that proves the pattern, not that AEI1 passes.

| ID | Attack | Required refusal | Nearest existing test |
|---|---|---|---|
| N1 | Modified receipt (any digest-covered field, incl. each added field) | signature invalid | interplane `tests/evaluation.rs` `spark_rsi_receipt_with_any_field_changed_fails` :586; protocols `evaluator_protocol_tests.rs` :109 |
| N2 | Missing record (delete a Cortex record, a transcript record, or a required evaluator outcome) | gap / chain / missing-evaluator | TRN1 `GAP`/`CHAIN` vectors (`vectors/expected.txt:3-5`); protocols `evaluator_protocol_tests.rs` :184; interplane `real_chain.rs` :223 |
| N3 | Reordered events (swap two records, or an effect before its generation record) | chain / order | TRN1 `CHAIN`; interplane `effect_binding.rs` :274, `real_chain.rs` :260 |
| N4 | Altered policy file (policy, holdout set, thresholds) | `policy_bundle_digest` / `policy_digest` mismatch | interplane `evaluation.rs` `altered_policies_are_refused` :327; protocols `evaluator_protocol_tests.rs` :94 |
| N5 | Replayed observation (same id, different record; same `execution_id`, other candidate; receipt reused for another candidate) | conflict / replay | spark-rsi `admit_production_quota` id-conflict branch; interplane `a_genuine_receipt_for_other_bytes_is_a_substituted_change` :301 |
| N6 | Unsigned (receipt, observation, or transcript digest not in a signed receipt) | unsigned / untrusted source | interplane `wrong_keys_are_refused` :276 (receipt only; observation case has no test) |
| N7 | Mismatched candidate (`subject_digest` or observation `candidate_digest` differs from admitted bytes) | subject mismatch | spark-rsi `admit_production_quota` digest check; interplane `evaluation_subject_mismatch` code (evaluation.rs `check`) |
| N8 | Self-approval: `proposer == verifier.principal_id`, or the verifier key is held by the proposing subsystem, or the candidate modified the evaluator, thresholds or verifier keys | refuse, never `Pass` | none. Rule from specs/evaluation/SPEC.md:14 (Immutability Invariant). Test is OPEN Q11 |
| N9 | Fixture presented as production (`evidence_class` flipped, fixture-signed observation, fixture file in production loader) | class / untrusted source | none |
| N10 | Wrong tier or fingerprint (receipt claims Tier4 but was signed with a software key) | tier mismatch | none; `verify` ignores both today (lib.rs:591-601) |
| N11 | Transcript valid but receipt `execution_id` / `transcript_digest` differs | join mismatch | none |
| N12 | Stale pin: consumer built against an aien-protocols commit not equal to the receipt's `protocol_version` contract | refuse at build or load | none |

Also required: a **negative control** per row (a deliberately defective verifier that skips that check must be caught), in the style of interplane `conformance/negative-controls.json:4-13` and TRN1 `mutate-verifier.sh`.

## 7. Pin and version rule

- **P1** Every consumer pins aien-protocols by full 40-character commit, in its own manifest (git `rev`), never by a path to a sibling checkout and never by a bare tag like `v0.1.0`. CI MUST fail if the pin and any pins file disagree (interplane already does this for its own PINS: `adapters/aien/PINS` comments, "CI checks that Cargo.toml and this line agree").
- **P2** Adopting a new commit is recorded in `CONSUMERS.md` in the same change.
- **P3** A change to the AEI1 digest layout bumps `protocol_version` (section 2.1) and the contract version of this file.

Stale or unpinned consumers found by the Milestone 0 inventory (aien-protocols head `407487b7e163`):

| Consumer | Current pin | Evidence |
|---|---|---|
| interplane `adapters/aien` | `AIEN_PROTOCOLS_REV=3a4cdbe8d360` (not head; lag in commits UNVERIFIED) | `interplane/adapters/aien/PINS` |
| spark-rsi | path dep `../aien-protocols/crates/aien-protocol-types`, `aien-evaluation-protocol`, `aien-probe`, no rev | `spark-rsi/Cargo.toml:43-45` |
| spark-inquisitor (ARCHIVED) | unpinned path deps | `spark-inquisitor/Cargo.toml:14-16` |
| aegis-runtime, aien-local-stack, aien-sovereign-core | `v0.1.0` by path | `CONSUMERS.md:3-12` |
| benchmarks | no aien-protocols dependency; depends on absent sibling | `benchmarks/Cargo.toml:18-22` |
| `CONSUMERS.md` row `spark-inquisitor` | stale (repo archived; canonical copy has no protocols dep) | evidence-chain.md sec. 3 |

## 8. OPEN questions (not decisions)

1. **World identity.** No type exists. What is a "world" id: a digest of the omega `RxWorld` config, a name, or a Cortex subject id? Receipt `world_id` cannot freeze until answered.
2. **Adapters.** Is `rsi-eval/2` (interplane) re-signed into AEI1 by a new adapter, or does spark-rsi switch to `EvaluationReceipt`? Same for the prime-race receipt. (Rule A1 forbids a fourth format either way.)
3. **Generation.** `CxHeader.generation` (rx_cortex.h:121) or `RxLivingProvenance.epoch` (rx_living.h:90)? They may not be the same counter.
4. **Cortex chain reachability.** What check proves `cortex_chain_head` belongs to a journal a consumer can open? `cx_verify` (rx_cortex.h:230) verifies one object by id, not a chain head.
5. **Transcript writer separation.** How does omega or sovereign-core keep the TRN1 writer outside the candidate's authority? No existing mechanism cited.
6. **Time units.** ms (`observed_at_ms`) versus micros (`Timestamp`).
7. **Status vocabulary** for observations.
8. **Resource cost metrics** required beyond `latency_us`.
9. **Replay window** between observation time and receipt times.
10. **Synthetic marker enforcement**: how to guarantee a production key can never sign `Synthetic`.
11. **Self-approval test**: what exactly identifies "the same subsystem" (principal string, key, or build digest)? `trusted_build_digest` (lib.rs:226) is the only candidate identifier found.
12. **Approval binding.** interplane's AIEN adapter uses a shared-secret HMAC (`compose_ledger.rs:94,132,190`), not public-key signatures. Does AEI1 replace it for adaptive evidence?
13. **Tier floor.** Which `CryptographicTier` (lib.rs:231-240) is the minimum for production: Tier2 software or Tier4 TPM only?

Questions that block freeze: 1, 3, 11. Questions that block only M5/M6: 6 to 10.
