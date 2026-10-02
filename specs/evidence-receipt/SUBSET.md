# Evidence Receipt (EvidenceReceiptV1): the subset VC1 needs

**Status**: Partial extraction, 2026-10-02 (VC1-FMT). This is NOT the full wire specification of the receipt. It records only what [Verified Crumb V1](../verified-crumb/SPEC.md) binds to. **The full extraction (decode rules, tier and mutation rules, ledger and lease store checks, JSON rendering) is owed.**
**Contract version**: 0.1.0 (major zero, see VERSIONING.md)
**License**: Community Specification License 1.0
**Authority**: the Rust source below. Where this file and the source differ, the source (as pinned) wins and this file is wrong.
**Pinned source**: `aien-dev/aien-sovereign-core` commit `40dd373`, `crates/aien-proof/src/` (read 2026-10-02). Line numbers are for that commit.

## 1. Receipt identity (what VC1 binds to)

- The receipt id is the BLAKE3 hash (32 bytes, shown as 64 lowercase hex digits) of the canonical byte encoding. `evidence.rs:7-12` (module rule), `receipt_id` at `evidence.rs:657-660`.
- The human-readable JSON form is not canonical and never hashed. `evidence.rs:8-9`.
- The `id` field is not part of the hashed bytes. `evidence.rs:453-620` (no `id` is written).
- Domain tag: ASCII `AIEN_EVIDENCE_RECEIPT_V1` (24 bytes), `evidence.rs:22`, written first at `evidence.rs:546`.
- Strings are an 8-byte big-endian length followed by the bytes (`push_str`, `evidence.rs:433-437`); counts are 4-byte big-endian (`push_u32`, `evidence.rs:438-441`); integers are big-endian.
- Lists (`input_artifacts`, `output_artifacts`, `dependencies`, `external_refs`, `required_features`) are sorted and de-duplicated before encoding (`sorted_unique`, `evidence.rs:446-451`); assertions are sorted by id (`evidence.rs:569`). Receipt `dependencies` are written as raw 32-byte hashes (`evidence.rs:579-585`).

## 2. Canonical field order (`evidence.rs:545-619`)

domain tag, `u32` version (1), `kind`, `tier` (string), `result` (1 byte: PASS 0, FAIL 1, BLOCKED 2, INCOMPLETE 3, SKIPPED 4; `evidence.rs:61-69`), `repo`, `commit`, `dirty` (1 byte), `toolchain`, `procedure`, `machine`, `env_class`, `input_artifacts` (count then strings), `output_artifacts` (count then strings), assertions (count then `id`, `expected`, `observed`, `pass` byte, `source`, `note`), `dependencies` (count then raw 32-byte ids), `declared_mutation` byte, `observed_mutation` byte, `authority`, `output_digest` (32 raw bytes), `external_refs`, `ledger` (0, or 1 then `u64` index and 32 raw bytes), `lease` (0, or 1 then 32 raw bytes and `resource`), `timestamp` `u64`, `required_features`, trailing `u32` zero (`evidence.rs:619`).

## 3. Fields VC1 reads

Struct `Receipt`, `evidence.rs:294-343`:

| Field | Type | VC1 use |
|---|---|---|
| `id` | BLAKE3 hex | must equal `verification.receipt_id` |
| `kind` | string | must equal `verification.verifier_profile` |
| `tier` | enum, `evidence.rs:85-102`, rank at `evidence.rs:133-143` | must satisfy the profile minimum; `TEST_ONLY_TRUST` satisfies nothing but itself (`chain.rs:259-267`) |
| `result` | verdict | must be `PASS` |
| `input_artifacts` | `<algo>:<hex>` strings, algos `blake3`, `sha256`, `sha512` (`evidence.rs:412-431`) | must list the VC's `semantic_id` and `source_or_ir_digest` as `sha256:<hex>` |
| `output_digest` | 64 hex digits, BLAKE3 of the captured output (`evidence.rs:130-131`, checked at `evidence.rs:490-494`) | must equal `verification.evidence_root` |
| `dependencies` | receipt ids | must equal the receipt ids of the VC's dependencies |

## 4. Verification entry points VC1 relies on

- `verify_bytes` (`evidence.rs:849-860`): parse JSON, recompute the id, refuse on mismatch.
- `verify_with_store` (`evidence.rs:907-930`): identity, consistency, ledger and lease bindings.
- `load_receipt` (`evidence.rs:932-948`): store path `<store>/receipts/<id>.json`, refuses a file whose bytes hash to another id.
- `verify_chain` / `verify_graph` (`chain.rs:46`, `chain.rs:157`): cycle is FAIL, missing dependency is INCOMPLETE, any non-PASS reachable receipt blocks, `TEST_ONLY_TRUST` ancestry cannot support `PRODUCTION` (`chain.rs:1-14`).

## 5. A second, different "EvidenceReceiptV1" exists

`tools/aien-test` in the same repo writes a receipt with schema string `aien-test/EvidenceReceiptV1`, canonical JSON, SHA-256 digest, stored as `<digest>.json` (`tools/aien-test/src/evidence.rs:1`, `:16`, `:23`, `:127-134`). It is NOT the aien-proof receipt (BLAKE3 over binary canonical bytes). VC1 binds only to the aien-proof id until the two converge. A VC whose `receipt_id` is an aien-test digest is refused as `RECEIPT_HASH_MISMATCH` by any resolver that uses the aien-proof store.

## 6. Owed

Full extraction of: `decode_canonical` rules (`evidence.rs:721-848`), tier/mutation limits (`evidence.rs:624-654`), ledger and lease store checks (`ledger_bind.rs`, `lease.rs`), the JSON field renderings, and golden vectors for the receipt itself. Convergence of the aien-test receipt with this one needs an owner decision.
