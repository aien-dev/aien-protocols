# Verified Crumb: VerifiedCrumbV1 (VC1)

**Status**: Draft v0 (VC1-FMT, stage 1 of the Verified Crumb program, 2026-10-02). Not yet produced or consumed by any runtime.
**Contract version**: 0.2.0 (major zero: may change by minor bump, see VERSIONING.md)
**Format version field**: `1`
**License**: Community Specification License 1.0
**Reference checker**: [`tools/vc1-check.c`](tools/vc1-check.c), C99, self-contained (own SHA-256, libc only)
**Golden vectors**: [`golden/`](golden/) with [`golden/expected.txt`](golden/expected.txt); built independently by [`tools/make-golden.sh`](tools/make-golden.sh), run by [`tools/check-golden.sh`](tools/check-golden.sh)
**Receipt binding**: [`../evidence-receipt/SUBSET.md`](../evidence-receipt/SUBSET.md)
**Decision record**: ARCH-0029, `aien-dev/aien-architecture` `docs/adr/0029-verified-crumbs-single-dependency-resolver.md` (merged at `ed0cf93`). The ADR fixes the decisions and the field names; this spec fixes the bytes.

## 0. Names and authority

- **Digests are authority. Names are convenience.** A name (in source, in `omega.lock`, in a store index) only helps a human find a digest. No decision to trust anything is ever made from a name.
- **A Verified Crumb is not a `.crumb` file and not Crumbline.** `.crumb` (RFC-0001) is agent coordination: who is editing which directory. Crumbline is the learning curriculum. A Verified Crumb (VC) is a third thing: a record that binds one Omega program to the receipt that proved it. They share the word "crumb" and nothing else; no tool for one reads the other.

## 1. Purpose

Omega already has a library of verified programs. VC1 defines the portable record that makes that library the only legal dependency resolver: a program may depend only on programs whose VC, receipt and dependencies all check out, all the way down. Resolution that cannot prove this refuses. There is no warning mode and no bypass (section 7).

## 2. The record

VerifiedCrumbV1 is the following, in this order:

| Field | Type | Meaning |
|---|---|---|
| `format_version` | u32 | `1`; every other value is refused |
| `semantic_id` | 32 bytes | the Omega program id (section 4.1) |
| `contract_id` | 32 bytes | identity of the program's contract (section 4.2) |
| `digest_kind` | u8 | what `source_or_ir_digest` covers: `0x01` canonical source, `0x02` canonical IR (section 4.3); any other value is refused |
| `source_or_ir_digest` | 32 bytes | SHA-256 of the exact source or IR bytes the verifier checked (section 4.3) |
| `realization_ids[]` | 0 to 256 x 32 bytes | digests of realizations of this program (section 4.4) |
| `dependencies[]` | 0 to 256 x {`semantic_id` 32, `required_contract` 32} | what this program imports, and under which contract |
| `verification` | {`receipt_id` 32, `verifier_profile`, `verifier_version`, `evidence_root` 32} | the proof (section 5) |
| `exports[]` | 0 to 256 strings | names this program offers |
| `capabilities[]` | 0 to 256 strings | capabilities this program needs |

No field is optional. An empty list is a count of zero.

The record has no `name` field. ARCH-0029 Decision 1 lists `name` as human-readable metadata carried in the name index, never authority and never used in resolution; it is not part of the VC bytes and not part of the VC id. `format_version` = `1` is the number for ARCH-0029's `VerifiedCrumbV1` tag.

## 3. Canonical byte encoding

Explicit bytes. No host struct, no padding, no alignment, no floating point, no text formatting. The same rules as the receipt encoding (`aien-proof` `evidence.rs:433-445`: big-endian integers, length-prefixed strings, domain tag first), so one reader style serves both.

### 3.1 Primitives

- `u32`: 4 bytes, big-endian. Counts are `u32`.
- `id`: exactly 32 raw bytes.
- `string`: `u64` big-endian byte length, then the bytes. Length 1 to 256. Every byte in `0x21` to `0x7E` (printable ASCII, no space).

### 3.2 Layout

```
domain tag                      22 bytes, ASCII "AIEN_VERIFIED_CRUMB_V1" (no terminator)
format_version                  u32 = 1
semantic_id                     id
contract_id                     id
digest_kind                     u8 (0x01 source, 0x02 IR)
source_or_ir_digest             id
realization count N             u32      then N x id
dependency count M              u32      then M x (semantic_id id, required_contract id)
verification.receipt_id         id
verification.verifier_profile   string
verification.verifier_version   string
verification.evidence_root      id
exports count                   u32      then strings
capabilities count              u32      then strings
(end of input: no trailing byte)
```

### 3.3 Ordering and uniqueness (canonical form)

- `dependencies` are sorted ascending by `semantic_id`, compared as unsigned bytes from the first byte (`memcmp`). Two entries with the same `semantic_id` are refused even if their `required_contract` differs.
- `realization_ids` are sorted ascending as unsigned bytes and unique.
- `exports` and `capabilities` are sorted ascending as unsigned bytes and unique.
- An encoder sorts its lists, then refuses duplicates. A decoder never sorts: unsorted input is refused, because a different byte order would be a different VC id.
- `semantic_id`, `contract_id`, `source_or_ir_digest`, `evidence_root`, and both ids inside every dependency entry must not be all zero. `receipt_id` must not be all zero (a zero receipt id is "no receipt": `MISSING_RECEIPT`).
- A dependency whose `semantic_id` equals the VC's own `semantic_id` is a cycle of length one: `DEPENDENCY_CYCLE`.
- Every list holds at most 256 entries (ARCH-0029 Decision 1: no cap below library capacity; the omega library holds 128 programs, `omega/src/omega_library.h:9`). Over the limit is refused, never truncated (the current omega library silently truncates dependencies at 8: `omega/src/omega_library.c:202`, `omega_library.h:10`; VC1 forbids that).

### 3.4 VC id

`vc_id = SHA256(canonical bytes)`, 32 bytes, where the canonical bytes begin with the domain tag. The tag is therefore part of the hashed input; a hash of the bytes without the tag is a different value and must not be used. The VC id names one exact record; it is not the program id and not the receipt id.

Why SHA-256: omega's identities are SHA-256 (`omega_program.h:83`) and this repo already carries a SHA-256 in C (`specs/execution-transcript/tools/trn1_verify.c:53-117`). The receipt id inside the record stays BLAKE3, because it must equal the aien-proof id (section 5).

### 3.5 Refusal order

A decoder reads fields in layout order and the first failure wins, so the code is a function of the bytes alone: domain tag, version, `digest_kind`, zero ids, realization order, each dependency in turn (self-dependency, zero ids, then duplicate or unsorted order against the previous entry), zero receipt id, strings, zero evidence root, exports order, capabilities order, trailing bytes. Reading past the end of input is `TRUNCATED` at that point.

### 3.6 Format refusal codes

| Code | When |
|---|---|
| `BAD_DOMAIN_TAG` | first 22 bytes are not the tag |
| `UNKNOWN_FORMAT_VERSION` | `format_version` is not 1 |
| `TRUNCATED` | input ends inside a field |
| `TRAILING_BYTES` | bytes remain after the last field |
| `DUPLICATE_DEPENDENCY` | equal `semantic_id` in adjacent dependency entries |
| `UNSORTED_DEPENDENCIES` | dependency `semantic_id` lower than the previous one |
| `NONCANONICAL_SET` | realizations, exports or capabilities unsorted or duplicated |
| `BAD_STRING` | length 0, length over 256, or a byte outside `0x21` to `0x7E` |
| `BAD_DIGEST_KIND` | `digest_kind` is not `0x01` or `0x02` |
| `ZERO_ID` | an all-zero id where section 3.3 forbids it |
| `TOO_MANY_ENTRIES` | a count over 256 |
| `MISSING_RECEIPT` | all-zero `receipt_id` (also a resolve code) |
| `DEPENDENCY_CYCLE` | self-dependency (also a resolve code) |

## 4. Field definitions

### 4.1 `semantic_id`

IS the Omega program id: `SHA256("omega.program.v2" 0x00 || body_root_id || in_type_id || out_type_id || pre_id || post_id)`, 32 bytes. Sources: `omega/src/omega_program.h:83` (formula), `:41` (domain string), `omega/src/omega_program.c:103-125` (`omega_program_compute_id`), `omega/src/omega_types.h:17,27-28` (`OMEGA_ID_BYTES` = 32, `SemanticId`). Omega commit `6fbf316`. VC1 defines no new derivation for this field.

### 4.2 `contract_id`

Omega has no single contract id today (UNVERIFIED by absence: grep of `omega/src` finds no function computing one; confidence 85%). The program id already hashes the four contract components (`omega_program.c:113-123`). VC1 therefore defines:

`contract_id = SHA256("aien.vc1.contract.v1" 0x00 || in_type_id || out_type_id || pre_id || post_id)`

with the same four 32-byte components as the program id, in that order. Stage VC1-LIB owns implementing it in omega. OPEN: this derivation is new and needs the omega owner's agreement (report item).

### 4.3 `source_or_ir_digest`

`digest_kind` says which: `0x01` canonical source, `0x02` canonical IR; any other value is refused (`BAD_DIGEST_KIND`). The digest is SHA-256 of the exact bytes the verifier checked. The kind sits in the canonical bytes, so the same digest bytes with a different kind give a different VC id (golden `v01_minimal` vs `v04_ir_kind`). Decided by the queen after inspection of PR 13; closes the former open question.

### 4.4 `realization_ids[]`

Opaque 32-byte digests of realization artifacts of this program. The derivation is owned by VC1-LIB and VC1-STORE (UNVERIFIED which hash omega uses for realizations; confidence 50%). VC1 only fixes how they are encoded and ordered.

## 5. The `verification` block and its receipt

`receipt_id` MUST be the aien-proof receipt id: the 32-byte BLAKE3 of the canonical bytes with domain `AIEN_EVIDENCE_RECEIPT_V1`. Source: `aien-sovereign-core` `crates/aien-proof/src/evidence.rs:453-620` (`canonical_bytes`), `:657` (`receipt_id`), pinned commit `40dd373`; wire subset in [`../evidence-receipt/SUBSET.md`](../evidence-receipt/SUBSET.md). VC1 invents no second receipt identity. The 64 hex digits of the receipt file name are these 32 bytes.

**Open item.** `tools/aien-test` currently writes a different receipt: schema string `aien-test/EvidenceReceiptV1`, canonical JSON, SHA-256 digest (`tools/aien-test/src/evidence.rs:1,16,23,127-134`). VC1 binds only to the aien-proof id until the two converge. A VC naming an aien-test digest as `receipt_id` is refused (`RECEIPT_HASH_MISMATCH`).

`verifier_profile` and `verifier_version` are strings (section 3.1). A resolver holds a profile table (profile name to minimum version and minimum tier). VC1 reserves no profile names; the first real entries are defined by VC1-STORE and VC1-CI. Golden vectors use `test-profile` / `1.0.0`.

### 5.1 Receipt binding rules (checked by the resolver, not by `vc1-check`)

For the receipt stored at `<store>/receipts/<receipt_id as hex>.json`, all of these must hold:

1. aien-proof `verify_with_store` accepts it (`evidence.rs:907`): the id recomputes from the canonical bytes.
2. `receipt.result` is `PASS`, and `receipt.tier` is at least the profile minimum (default `HOST_TEST`), never `TEST_ONLY_TRUST` (`chain.rs:259-267`).
3. `receipt.output_digest` (32 bytes) equals `evidence_root`.
4. `receipt.input_artifacts` lists `sha256:<hex semantic_id>` and `sha256:<hex source_or_ir_digest>`.
5. `receipt.kind` equals `verifier_profile`.
6. `receipt.dependencies` equals the sorted set of the `receipt_id` of each dependency's VC (duplicates collapse, as aien-proof sorts and de-duplicates receipt dependencies, `evidence.rs:446-451,579`; so aien-proof `verify_chain`, `chain.rs:46`, also walks the closure).

These are VC1 design decisions, not facts about aien-proof today (OPEN: confirm with the aien-proof owner; report item). The receipt cannot contain the VC id (the VC contains the receipt id), so the binding runs through `semantic_id` and `source_or_ir_digest`.

## 6. Resolve rule

Inputs: a lockfile (section 8), a store keyed by `semantic_id`, a profile table, and a domain (section 7). The resolver MUST proceed in this order and MUST refuse on the first failure. It never returns a partial closure.

1. **Lock.** Each imported name is looked up in `omega.lock`. An import with no line in the lock, or an absent or malformed lock: `DEPENDENCY_NOT_PINNED`. A lock line whose name the source never imports: `UNVERIFIED_DEPENDENCY` (a pin with no import behind it; section 6.2).
2. **Store.** Fetch the VC by the locked `semantic_id`. The name index is never consulted for trust. Absent: `UNVERIFIED_DEPENDENCY`.
3. **Identity.** Decode the VC (format refusals, section 3.6). Its `semantic_id` must equal the key it was fetched by, and the program recomputed from the stored source or IR must have that id (`omega_program_compute_id`) and that `source_or_ir_digest`. Mismatch: `UNVERIFIED_DEPENDENCY`. The locked `receipt` must equal `receipt_id`: else `RECEIPT_HASH_MISMATCH`.
4. **Taint.** In `omega-build`, a VC that the store marks tainted, or that lists the reserved capability `omega-dev.taint`, is refused: `TAINTED_ARTIFACT`. (ARCH-0029 Decision 5: omega-dev output never enters the store, so this is defence in depth; the reserved capability name is a VC1 proposal, OPEN.)
5. **Profile.** `verifier_profile` not in the profile table: `UNKNOWN_VERIFIER_PROFILE`. `verifier_version` below the table minimum: `VERIFIER_TOO_OLD` (a VC1 addition; ARCH-0029 Decision 9 has no code for it, and an earlier draft of this spec wrongly used `STALE_RECEIPT` for it).
6. **Receipt.** Receipt missing from the store: `MISSING_RECEIPT`. Receipt fails rule 1, 3, 5 or 6 of section 5.1, or rule 4 for the `semantic_id` (it does not name this program): `RECEIPT_HASH_MISMATCH`. Receipt names this `semantic_id` but not the current `source_or_ir_digest` (it covers an older source: it predates a change to the source it covers, ARCH-0029 Decision 9 code 6): `STALE_RECEIPT`. Receipt not `PASS` or tier too low: `UNVERIFIED_DEPENDENCY`.
7. **Edges.** Each dependency entry's VC (resolved by steps 2 to 7 with the entry's `semantic_id`, and no lock) must have `contract_id` equal to `required_contract`, else `UNVERIFIED_DEPENDENCY`. A dependency already on the current resolution path: `DEPENDENCY_CYCLE`.
8. **Declared imports.** The set of programs the VC's stored source or IR actually imports must equal the set of `semantic_id` in `dependencies[]`. An import with no `dependencies[]` entry: `UNDECLARED_IMPORT`. A `dependencies[]` entry that the stored source or IR does not import: `UNVERIFIED_DEPENDENCY`. Section 6.2 has the one table for this and the equivalent checks in the lock and in a component manifest. OPEN (UNVERIFIED, confidence 70%): how an import in a stored source is mapped to a `semantic_id` (the name has no lock in this step) is not defined by this spec; VC1-STORE and omega own it. No implementation executes this step today.
9. **Closure.** The union of all visited VCs is the transitive closure. A resolution succeeds only if every VC in it passed 2 to 7.

### 6.1 Resolve refusal codes

`UNVERIFIED_DEPENDENCY`, `MISSING_RECEIPT`, `RECEIPT_HASH_MISMATCH`, `DEPENDENCY_NOT_PINNED`, `DEPENDENCY_CYCLE`, `STALE_RECEIPT` (the receipt predates a change to the source it covers), `UNDECLARED_IMPORT`, `TAINTED_ARTIFACT`, `UNKNOWN_VERIFIER_PROFILE` (the nine ARCH-0029 Decision 9 codes, same meanings; the declaration codes `DEPENDENCY_NOT_PINNED`, `UNDECLARED_IMPORT` and `UNVERIFIED_DEPENDENCY` are pinned down in section 6.2), plus the VC1 addition `VERIFIER_TOO_OLD`. They are names, not numbers; a consumer may map them to its own exit codes. Format refusals (section 3.6) also refuse a resolution.

### 6.2 One meaning per code for declaration checks

Three places can declare what a program depends on: the lock (`omega.lock`, a digest pin per name), a component manifest (the declared dependency list of a unit such as an `aien-closure` `[deps]` table), and the VC (`dependencies[]`). The program itself says what it actually uses: its imports, or for a Rust component its edges in the build graph. Every disagreement between the two maps to exactly one of the existing nine codes. No code is added.

| Situation | Code |
|---|---|
| An import (or actual edge) has no line in the lock, or its manifest entry carries no receipt pin or a pin that is not the dependency's own receipt | `DEPENDENCY_NOT_PINNED` |
| A lock line names something the source never imports | `UNVERIFIED_DEPENDENCY` |
| A declared dependency (manifest entry, or `dependencies[]` entry) that is not an actual import or edge | `UNVERIFIED_DEPENDENCY` |
| An actual import or edge that the manifest does not declare | `UNDECLARED_IMPORT` |
| The VC's stored source or IR imports a program with no `dependencies[]` entry (step 8) | `UNDECLARED_IMPORT` |
| A `dependencies[]` entry the VC's stored source or IR does not import (step 8) | `UNVERIFIED_DEPENDENCY` |

The two rules behind the table:

- `UNDECLARED_IMPORT` means the program uses something its dependency list does not declare: the program does more than it says. This is the wording of ARCH-0029 Decision 9 code 7 ("an edge the manifest does not declare"). It never describes an extra declaration.
- An extra declaration (a pin or a listed dependency with no import behind it) is `UNVERIFIED_DEPENDENCY`: nothing verifies it as an edge of the program. ARCH-0029 Decision 9 code 1 words it as "no admissible receipt"; this spec reads that as covering a dependency that cannot be shown to be an edge, because the ADR has no code for extra declarations and the stage 5 specification may not add one. Extra declarations are refused, never ignored, so the closure digest and the receipt dependency list stay exact.

Precedence: where the missing declaration is a digest pin in the lock, `DEPENDENCY_NOT_PINNED` wins over `UNDECLARED_IMPORT`; `UNDECLARED_IMPORT` is for a missing entry in a dependency list that is not the lock (manifest or `dependencies[]`). When several rows apply, the first failing step of section 6 reports.

## 7. The two domains

- **omega-dev.** Exploratory. Anything it produces is TAINTED. It may read verified crumbs. Its output is not a VC (it has no receipt), never enters the store, and can never satisfy an import in `omega-build` (ARCH-0029 Decision 5).
- **omega-build.** The verified compiler. It accepts a program only if the full closure resolves under section 6. There is no flag, environment variable, file, command line or fallback that lets it read a name, a non-VC, a tainted artifact or an unverified dependency. Any such switch is a defect in the build, not a feature.
- The boundary is one-way: omega-build may consume only VCs; nothing built in omega-dev is promoted except by being verified into a new VC through the normal path.

## 8. Lockfile: `omega.lock`

UTF-8 text, LF line endings, no tabs.

```
omega.lock v1
# comment lines start with #; blank lines are ignored
add = semantic 1111111111111111111111111111111111111111111111111111111111111111 receipt 5555555555555555555555555555555555555555555555555555555555555555
```

- Line 1 is exactly `omega.lock v1`.
- Entry grammar: `NAME = semantic HEX64 receipt HEX64`, single spaces. `NAME` is `[A-Za-z_][A-Za-z0-9_.-]{0,127}`. `HEX64` is 64 lowercase hex digits.
- Entries are sorted by `NAME` (unsigned bytes) and names are unique.
- `semantic` pins the program id; `receipt` additionally pins the receipt id (ARCH-0029 Decision 3 has the lockfile map imports to a `semantic_id`; the `receipt` pin is a VC1 addition, so a store entry swapped for another receipt is caught at the lock). Resolution requires both to match the VC found in the store (section 6, steps 2 and 3).
- The name is a label the importing source uses. The pair of digests is the dependency.
- Any other line is a malformed lock: `DEPENDENCY_NOT_PINNED`.

## 9. Conformance

`golden/expected.txt` has one line per vector: `NAME ACCEPT <vc id hex>` or `NAME REFUSE <CODE>`. `tools/check-golden.sh` regenerates the vectors, runs the C checker (with ASan/UBSan when available), recomputes every ACCEPT id with `sha256sum` (independent of the C code), proves three vector mutants (flip a byte, reorder dependencies, drop the domain tag) are detected, and proves nine deliberately broken checker builds (unsorted deps, zero receipt, no domain tag in the hash, duplicates, trailing bytes, zero ids, string bytes, entry count limit, digest kind) all fail the corpus.

| Vector | Result |
|---|---|
| `v01_minimal`, `v02_deps`, `v03_capabilities`, `v04_ir_kind` | ACCEPT with fixed ids (`v04` is `v01` with `digest_kind` 0x02: a different id) |
| `r01_duplicate_dep` | `DUPLICATE_DEPENDENCY` |
| `r02_unsorted_deps` | `UNSORTED_DEPENDENCIES` |
| `r03_zero_receipt_id` | `MISSING_RECEIPT` |
| `r04_self_dependency` | `DEPENDENCY_CYCLE` |
| `r05_trailing_byte` | `TRAILING_BYTES` |
| `r06_unknown_version` | `UNKNOWN_FORMAT_VERSION` |
| `r07_truncated` | `TRUNCATED` |
| `r08_bad_domain_tag` | `BAD_DOMAIN_TAG` |
| `r09_unsorted_exports` | `NONCANONICAL_SET` |
| `r10_bad_digest_kind` | `BAD_DIGEST_KIND` |
| `r11_zero_id` | `ZERO_ID` |
| `r12_bad_string` | `BAD_STRING` |
| `r13_too_many_entries` | `TOO_MANY_ENTRIES` |

Vector files are lowercase hex, one line, ending in a newline.

## 10. Versioning

Contract 0.2.0. While major is zero, a change to the byte layout, the id derivation or a code name is a minor bump with migration notes in CHANGELOG.md (VERSIONING.md). `format_version` changes only when the layout changes; a decoder refuses versions it does not know.

## 11. Limits (stated, not hidden)

- `vc1-check` covers format and id only. It does not read lockfiles, stores or receipts, and does not implement BLAKE3, so section 5.1 and section 6 are specified here but not yet executed by any tool. Stages VC1-STORE, VC1-RESOLVE and VC1-CI implement them.
- The declaration table in section 6.2 is not covered by golden vectors: a golden vector is one VC, and these checks compare a program's imports with a lock, manifest or VC, which needs a source or a build graph. Implementations carry the tests: `aien-closure` (rows for manifest and edge), omega `omega_resolve` (rows for lock and imports). Step 8 proper (stored source against `dependencies[]`) is executed by no implementation yet.
- Sections 4.2, 4.4, 5.1 and the profile table are design proposals awaiting owner agreement.
- Golden ids come from synthetic ids (repeated bytes), not from real programs.
- `NONCANONICAL_SET` is vectored only for exports (not realizations or capabilities).
