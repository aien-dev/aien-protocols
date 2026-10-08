# OSC Unit Artifact v1 FROZEN (signed container for an OSC-compiled Omega unit)

**Status**: v1 FROZEN (2026-10-08, reviewed by session ee6210 at cee67fe). Change control: any change to this container is a new `container_version` (a v2 draft), never an edit of v1.
**Container version field**: `1`
**License**: Community Specification License 1.0
**Origin**: `aien-dev/aien-architecture#158` and `#162` (Campaign 3). Shared contract between the AIENOS loader and task work and OSH (the Omega-native shell).
**Claims no implementation**: no loader, no packer and no launcher for this container exists. The only things that have run are the shell generator and the shell reference checker in this directory (section 14).
**Conformance vectors**: [`vectors/`](vectors/), [`vectors/expected.txt`](vectors/expected.txt), `lookups.txt`, `state.txt`, `launch.txt`, built by [`tools/make-vectors.sh`](tools/make-vectors.sh), judged by [`tools/osc-unit-check.sh`](tools/osc-unit-check.sh) and [`tools/osc-launch-check.c`](tools/osc-launch-check.c), proven together by [`tools/check-vectors.sh`](tools/check-vectors.sh)
**Ground truth read**: omega `osh/osc-ext-bytes` at `d64ccb3` (`src/compiler/osc_ir.c:599-610, 689-705`, `osc_ir.h:31-40, 151-176, 252`, `osc_rt.h:32, 70, 85-99`, `osc_cg.c:143-159`, `osc_a64.c:28-93`, `oscc_main.c`, `docs/osc/OSC-1-DESIGN.md` section 7); aienos `main` at `c63d6db` (ADR 0013, 0014, 0017; `native/kernel/artifact/ck_artifact.h`, `native/kernel/core/ipc.h`). Where this draft differs from them, section 2 says so.

## 1. Purpose and model

An OSC unit is the output of the OSC compiler for one source file: the canonical IR bytes of the unit and the AArch64 machine code generated from it. Today the host compiler emits no container: `osc_native_map()` copies raw code bytes into a page and makes it executable. This spec defines the container that carries a unit to a loader, so that AIENOS (and the Linux host adapter) can decide, from bytes alone, whether to admit and run it, and so that one result shape comes back.

Three parties:

- **Producer**: runs the compiler, builds the container, signs it. Holds a signing key.
- **Loader**: AIENOS kernel-side admission, or the host adapter. Holds trust anchors and a policy. Never runs unit code before every check in section 8 passes.
- **Launcher**: after admission, calls one entry function with arguments and reports the outcome (section 9).

The container is a byte format. No Rust enum, C struct or compiler layout crosses it.

## 2. Relation to AIENOS ADRs and named deviations

This container reuses the encoding style, hash and signature choices of Binary Artifact v0 (ADR 0014) so one set of parser habits and one crypto dependency serve both. It is a different format, because an OSC unit is not an EL0 program image. Every difference:

| # | ADR or code | This spec | Why |
|---|---|---|---|
| D1 | ADR 0014 section 2: exactly two sections (code, data), `entry_offset`, no extension area, `format_version` 0. | New magic `OSCUNIT\0`, four sections (IR, code, entry table, capability requests), its own `container_version`. A Binary Artifact v0 reader refuses it at magic. | A unit has several entry functions, carries its IR, has no data section, and is called with a hidden runtime pointer. |
| D2 | ADR 0014 section 3: the signature block, including signer fingerprint, is excluded from `ArtifactId`. | Signer class, algorithm and fingerprint are inside the signed header. The signature covers header and section table. | The TEST/OWNER label must not be strippable or swappable without breaking the signature. |
| D3 | ADR 0014 section 2.3: 48-byte capability request, no generation. Handles are issued at admission. | The 48-byte record is kept verbatim (same field rules). 16 bytes are appended: `domain` and `required_generation` (u64). | The request needs to say which generation of a resource it expects, and in which capability domain. See section 6.3. |
| D4 | ADR 0014 section 6: only a test anchor exists; production trust-anchor set is empty and fails closed. ADR 0017: TRUST-1 offline Owner Root. | Signer class `OWNER` means the key comes from the loader's local OWNER anchor set. v1 supports direct anchors only, no delegation chain. Until M5 provisions an OWNER anchor, every OWNER unit is refused `UNTRUSTED_SIGNER`. | Consistent with fail closed. Delegation from the Owner Root is an open item (section 13). |
| D5 | ADR 0013: `Handle` is `(generation << 32) \| index`, generation u32, nonzero. Kernel `ipc.h` and `caps` use u32 generations. | Requests carry u64 generations. Domain 1 (kernel IPC table) accepts only values that fit u32; anything wider is refused, never truncated. Domain 2 (hosted authority, u64) is refused by a loader that has no domain 2. | The OSH ABI draft (section 9, rule 3) already separates these domains. The 64 to 32 bridge is out of scope. |
| D6 | ADR 0014 section 2.4: resource envelope with code, data, stack pages, IPC and syscall limits. | Smaller declared limits (section 7). Page counts are derived by the loader from section sizes. | A unit has no data section and no IPC; its memory is the runtime pool and caller slices. It makes no system calls, which is enforced by the code scan (section 8.4) and the launch requirements (section 9.1.1), not assumed. |
| D7 | ADR 0014 section 4: maximum artifact 16 MiB. | Maximum container 2 MiB. | Limits in section 7 cap a unit well below that. |
| D8 | ADR 0014 section 7: Admission Receipt v0 binds `ArtifactId` and a payload digest of a Binary Artifact. | No receipt is defined here. The `UnitDigest` of section 5 is the value a future receipt amendment binds, and the value any authorization or execution request binds today (section 5.2). | A receipt change belongs to AIENOS, not to this container. |
| D9 | ADR 0014 refusal names are `CamelCase`. | Names are `UPPER_SNAKE` with stable numbers (section 8.3). Mapping where one exists: `BAD_MAGIC` = `BadMagic`, `CONTAINER_VERSION` = `UnsupportedVersion`, `ABI_VERSION` = `WrongAbi`, `TRUNCATED` = `Truncated`, `SECTION_OVERLAP` = `SectionOverlap`, `*_HASH_MISMATCH` = `DigestMismatch`, `UNTRUSTED_SIGNER` = `UntrustedSigner`, `BAD_SIGNATURE` = `BadSignature`, `LIMIT_EXCEEDED` = `ResourceLimit`. | This spec is shared with a non-Rust consumer. |

Consistent with ADR 0014 and not a deviation: little-endian fixed-width integers, no padding semantics beyond defined zero bytes, nonzero reserved bytes refused, unknown values refused, SHA-256, Ed25519 (RFC 8032 pure), signer key found only by fingerprint in the loader's local anchor set (the container never supplies a trusted key), domain-separated digests, the invariant "identified bytes = verified bytes = admitted bytes = mapped bytes = executed bytes" (section 8.2).

## 3. Encoding rules

- All integers are unsigned, fixed width, little-endian. No signed fields.
- Reserved bytes and reserved fields must be zero; nonzero is a refusal.
- Hashes are SHA-256, 32 bytes, in the ordinary byte order that `sha256sum` prints as hex.
- Every offset and length is checked with overflow-safe arithmetic against the real file length before any byte it names is read.
- A reader never skips unknown data. Unknown versions, flags, section kinds, algorithms and enum values are refusals.
- Domain tags below are ASCII bytes including the final NUL shown as `\0`.

## 4. Container layout

Total layout, in file order: header (128 bytes), section table (4 x 48 = 192 bytes), four sections, signature (64 bytes, last). `total_length` is the exact file length.

### 4.1 Header, 128 bytes at offset 0

| Offset | Size | Field | v1 rule |
|---:|---:|---|---|
| 0 | 8 | `magic` | ASCII `OSCUNIT\0` |
| 8 | 2 | `container_version` | `1` |
| 10 | 2 | `header_size` | `128` |
| 12 | 2 | `unit_format_version` | equals byte 7 of the IR section (`{'O','S','C','1','I','R',0,v}`). Loader accepts the set it supports; the conformance profile supports 1 to 5 (1 OSC-1, 2 structs, 3 arenas, 4 pools, 5 byte and cell slices). Anything else is refused. Old versions are never reinterpreted as newer ones. |
| 14 | 2 | `runtime_abi_version` | `1`: the OSC-1 call convention (section 9.1) and the `OscRt` fixed-offset table of `osc_rt.h` at `d64ccb3` (offsets 0 to 96). The loader refuses a value it does not provide. |
| 16 | 4 | `flags` | `0`. Every set bit is refused. |
| 20 | 4 | `total_length` | exact file length, 384 to 2,097,152 |
| 24 | 4 | `section_table_offset` | `128` |
| 28 | 2 | `section_count` | `4` |
| 30 | 2 | `section_entry_size` | `48` |
| 32 | 2 | `function_count` | `1..=32`; equals entry-table count |
| 34 | 2 | reserved | zero |
| 36 | 4 | `max_stack_bytes` | `4096..=1,048,576`, multiple of 16 |
| 40 | 8 | `cpu_ticks` | `1..=1,000,000,000` (same maximum as ADR 0014). A request for a CPU budget in the scheduler ticks of ADR 0014 section 2.4; the loader clamps it to its own maximum (section 9.1.1 item 5). |
| 48 | 2 | `pool_slots` | `0..=64`. Limits the array and arena slot pool (`OSC_RT_SLOTS` = 64, `osc_rt.h:32`) the unit may hold. The versioned-handle pools of unit format 4 and up (`OSC_RT_POOLS` = 8 pools of `OSC_POOL_SLOTS` = 16 slots, `osc_rt.h:70`, `osc_ir.h:176`) are fixed by the runtime and are not carried here. |
| 50 | 2 | reserved | zero |
| 52 | 4 | reserved | zero |
| 56 | 2 | `signer_class` | `1` TEST, `2` OWNER; others refused |
| 58 | 2 | `signature_algorithm` | `1` = Ed25519 |
| 60 | 4 | reserved | zero |
| 64 | 32 | `signer_fingerprint` | SHA-256 of the raw 32-byte Ed25519 public key |
| 96 | 32 | reserved | zero |

### 4.2 Section table, 4 entries of 48 bytes at offset 128

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 2 | `kind` | entry k (1-based) has kind k: `1` IR, `2` CODE, `3` ENTRY, `4` CAPS. Order and presence are fixed. |
| 2 | 2 | `flags` | zero |
| 4 | 4 | `offset` | from file start |
| 8 | 4 | `length` | bytes |
| 12 | 4 | reserved | zero |
| 16 | 32 | `sha256` | SHA-256 of exactly the `length` bytes at `offset` |

Canonical placement: section 1 at offset 320; each next section at the next multiple of 16 after the previous one ends; the gap bytes are zero; the signature starts exactly where section 4 ends, so `total_length = end of section 4 + 64`. Any other placement is refused (overlap and out-of-range placements are distinguished in section 8).

### 4.3 Sections

1. **IR** (kind 1): the canonical IR encoding as produced by `osc_ir_encode`, 8 to 1,048,576 bytes. Its SHA-256 is `ir_sha256`, the value `oscc` prints, and it is the unit identity (section 5.2).
2. **CODE** (kind 2): the AArch64 machine code of the whole unit as `osc_cg_compile` emits it, little-endian 32-bit words, 4 to 262,144 bytes (64 pages, the ADR 0014 code limit), length a multiple of 4. Its SHA-256 is `code_sha256`, as `oscc` prints. Position independent: calls between functions are relative `BL`, runtime calls go through `OscRt` in x7. The container has no relocations and no imports.
3. **ENTRY** (kind 3): `function_count` records of 96 bytes (section 6.1). Length exactly `96 * function_count` (otherwise `ENTRY_TABLE`).
4. **CAPS** (kind 4): 8-byte header then `count` records of 64 bytes (section 6.3). Length exactly `8 + 64 * count`, count `0..=16` (a wrong length is `CAPS_TABLE`, a count above 16 is `LIMIT_EXCEEDED`).

### 4.4 Signature, last 64 bytes

The raw 64-byte Ed25519 signature (section 5.1). It is excluded from every hash and digest.

## 5. Identity and signature

### 5.1 Digest and signature

```text
UnitDigest = SHA256( "AIENOS-OSC-UNIT-V1\0" || file[0 .. 320) )

signature  = Ed25519.Sign( private_key,
                           "AIENOS-OSC-UNIT-SIGNATURE-V1\0" || UnitDigest )
```

`file[0..320)` is the header and the section table. That range already contains every section's offset, length and SHA-256, the signer class and the signer fingerprint, so one signature binds all of them. Ed25519 means RFC 8032 pure Ed25519 over exactly that message; Ed25519ph and Ed25519ctx are not interchangeable. Verification is strict, as ADR 0014 requires (no local elliptic-curve implementation; the reviewed verifier dependency of ADR 0014). Strict includes rejecting a non-canonical signature: the 32-byte scalar `S` must be below the group order `L`, because the signature bytes are outside `UnitDigest` and an `S + L` variant would otherwise be a second valid file for the same unit (vector `r45`).

### 5.2 Unit identity

Two identities, with different jobs:

- **`UnitDigest`** (section 5.1) names one exact signed container: this IR, this code, these entry names, these limits, these requested capabilities, this signer class and key. **Execution and authorization bind to `UnitDigest`.** Any grant, policy entry, approval, resolve result or receipt that says "run this" or "this may run" names a `UnitDigest`, never an `ir_sha256`. Reason: a differently signed or differently built container with the same IR must not be swappable in under an authorization made for another container.
- **`ir_sha256`** (the IR section hash, as `oscc` prints it) is the **program identity**, carried for display and for recognising the same program across containers. It is never an authorization key and never sufficient to select what runs.

A loader or resolver that is given only an `ir_sha256` may use it to find candidate containers; it must then bind to one `UnitDigest` before anything runs.

## 6. Section contents

### 6.1 Entry record, 96 bytes

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 2 | `fn_index` | equals the record's position (0-based) and the function's index in the IR |
| 2 | 1 | `nregs` | argument registers used, `0..=6` (a slice uses two) |
| 3 | 1 | `ret_kind` | `0` void, `1..=9` a scalar kind below |
| 4 | 6 | `reg_kind[0..6]` | kind of each argument register; entries at index `>= nregs` are zero |
| 10 | 2 | reserved | zero |
| 12 | 4 | `code_offset` | byte offset of the function entry in CODE; multiple of 4; inside CODE; strictly increasing with `fn_index` |
| 16 | 16 | `name_hash` | first 16 bytes of SHA-256(`"AIENOS-OSC-FN-NAME-V1\0"` followed by the `name_len` name bytes). An index only (section 6.1.1). |
| 32 | 1 | `name_len` | `1..=63` |
| 33 | 63 | `name` | the function name, `name_len` bytes, then zero bytes up to 63 |

Kind numbers are the compiler's `OscScalar` values: `1` bool, `2` u8, `3` u16, `4` u32, `5` u64, `6` i8, `7` i16, `8` i32, `9` i64, `11` bytes (read-only slice pointer), `12` cells (writable u64 slice pointer). `10` (a pool reference) and `0` as an argument kind are refused. Kinds `11` and `12` are valid only when `unit_format_version` is 5 (`osc_ir.c:610`). A register of kind `11` or `12` must be followed immediately by a register of kind `5` (the slice length), which makes a two-register slice. #### 6.1.1 Names

- Charset: a name is 1 to 63 bytes matching `[A-Za-z_][A-Za-z0-9_]*` (ASCII; a subset of UTF-8; no other byte, so NUL, space, control and non-ASCII bytes are refused). The bytes after `name_len` up to the 63rd must be zero. A violation is `ENTRY_NAME`.
- `name_hash` must equal the hash of the carried name; otherwise `ENTRY_NAME_HASH`. Names within one unit must be pairwise different, and so must their `name_hash` values; otherwise `ENTRY_NAME_DUPLICATE`.
- **The hash is only an index.** A launcher may use `name_hash` to find candidate records quickly. It must then compare the requested name to the record's `name` byte for byte, with equal length, case sensitively. A hash match with a different name is not a match: the lookup fails `LAUNCH_BAD_ENTRY`. The hash is never the identity of a function, so a hash collision cannot run the wrong function.

The compiler's reported values for the vector unit are: `add` with registers (u64, u64), returns u64, offset 0; `first_byte` with registers (bytes, u64), returns u64, offset 60.

### 6.2 Honesty about the entry table

The loader does not parse the IR beyond its first 8 bytes. `function_count`, the entry records and the declared limits are signer attestations, like the code. A loader MUST NOT treat them as verified facts about the code. Entry names are likewise attested, not checked against the IR. A `code_offset` may point into the middle of a function: the table is not checked against function boundaries, so a launch at a bad offset is a control-flow primitive available to a malicious signer, which is inside the attestation boundary (section 10).

### 6.3 Capability header and request record

CAPS header, 8 bytes: `count` u16, then 6 reserved bytes (zero).

Request record, 64 bytes. Bytes 0 to 47 are the ADR 0014 section 2.3 capability request, with exactly its field rules (`resource_kind` `3` object or `2` channel; `flags` 0; `resource_id` nonzero; `rights` nonzero within the six ABI v1 bits; bounds kinds 1 and 2; positive `max_operations` and `max_bytes`; object `max_bytes <= byte_length`). Bytes 48 to 63:

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 48 | 2 | `domain` | `1` kernel IPC capability table (ADR 0013 handles; 32-bit generation). `2` hosted capability authority (64-bit generation). Others refused. |
| 50 | 2 | `flags` | zero |
| 52 | 4 | reserved | zero |
| 56 | 8 | `required_generation` | `0` means no generation requirement. Nonzero means the request is admissible only against a resource currently at exactly this generation (a stale value is refused `CAP_GENERATION_STALE`). |

Records are strictly sorted by (`domain`, `resource_kind`, `resource_id`); duplicates and disorder are structural refusals. Admission only ever reduces a request (ADR 0014: granted is a subset of requested); a request conveys no authority and the container never grants.

Generation rules, the part ADR 0013 forces:

- A loader MUST refuse a request it cannot represent. For domain 1 a nonzero `required_generation` above `0xFFFFFFFF` is refused `CAP_GEN_NOT_REPRESENTABLE`. There is no truncation, wrapping, hashing or "closest value". For a domain the loader does not provide, the refusal is `CAP_DOMAIN_UNSUPPORTED`. All records are checked for domain before any record is checked for generation, so one input has one first refusal (section 8.2 step 15; vector `r36`).
- This spec defines no conversion between a 64-bit hosted generation and a 32-bit kernel generation.

## 7. Limits

| Item | v1 maximum | Source |
|---|---|---|
| Functions per unit | 32 | `OSC_MAX_FUNCS` |
| Argument registers per function | 6 (a slice counts two) | `OSC_MAX_PARAMS`, `x0..x5` |
| Virtual registers per function | 480 | `OSC_MAX_VREGS` (compiler limit; not carried in the container) |
| Instructions per function | 4096 | `OSC_MAX_INSNS` (compiler limit) |
| Array length | 64 cells | `OSC_MAX_ARRAY_LEN` |
| Runtime pool slots | 64 | `OSC_RT_SLOTS` |
| IR section | 1 MiB | this spec |
| CODE section | 262,144 bytes | ADR 0014 code pages |
| Capability requests | 16 | ADR 0014 |
| Container | 2 MiB | this spec |
| `cpu_ticks` | 1,000,000,000 | ADR 0014 |

Loops are bounded and recursion does not exist in OSC; the container relies on that only through the signer's attestation (section 10). A loader may apply stricter limits, which belong to its build identity and cannot be relaxed by the container.

## 8. Admission

### 8.1 Loader inputs (local, never from the container)

The set of supported `unit_format_version` values; the `runtime_abi_version` values it provides; the build mode (`release` or `qualification`); the trust-anchor sets for class TEST and class OWNER (public keys, looked up by fingerprint); the capability domains it supports; its policy and hard maxima.

### 8.2 Rules

The loader copies the bytes into protected staging memory before parsing, and hashes and verifies the copy it will use. After copying code into its private pages and before making them executable it hashes those bytes again and requires `code_sha256` (ADR 0014 section 5; invariant: identified = verified = admitted = mapped = executed). Code pages are RX, never writable and executable together. The loader checks, in this order, and the first failure decides the result:

1. File shorter than 128 bytes: `TRUNCATED`.
2. Magic, then `container_version`, then the fixed header fields and reserved bytes, then `unit_format_version`, then `runtime_abi_version`, then `flags`.
3. `total_length` in range (`TOTAL_LENGTH`); file shorter than `total_length` (`TRUNCATED`); longer (`TRAILING_BYTES`).
4. Section table: kinds, flags, reserved (`SECTION_TABLE`); every section inside the file before the signature and not before offset 320, with overflow-safe `offset + length` (`SECTION_BOUNDS`); any two nonempty sections overlapping (`SECTION_OVERLAP`); canonical placement and zero gaps (`SECTION_LAYOUT`).
5. Limits of section 7 and the declared-limit ranges (`LIMIT_EXCEEDED`). Section sizes are range-checked here; the CAPS `count` is read here only when the CAPS section is at least 8 bytes, which step 4 has already bounds-checked.
6. `signer_class` (`SIGNER_CLASS`), `signature_algorithm` (`SIGNATURE_ALGORITHM`). Header work only, done before hashing up to 2 MiB.
7. Section SHA-256 values, in section order (`IR_HASH_MISMATCH`, `CODE_HASH_MISMATCH`, `ENTRY_HASH_MISMATCH`, `CAPS_HASH_MISMATCH`).
8. IR prefix `OSC1IR\0` and version byte equal to `unit_format_version` (`IR_MALFORMED`).
9. Code scan (section 8.4): every code word is in the OSC-emitted subset (`CODE_INSTRUCTION`).
10. Entry table: its length is exactly `96 * function_count` and its structure (`ENTRY_TABLE`); then per record `ENTRY_NAME`, `ENTRY_NAME_HASH`; after each record, a name or `name_hash` equal to an earlier record's is `ENTRY_NAME_DUPLICATE`. Slice register kinds (11, 12) need `unit_format_version` 5, else `ENTRY_TABLE`.
11. Capability table: its length is exactly `8 + 64 * count` and its records (`CAPS_TABLE`). A `count` above 16 was already `LIMIT_EXCEEDED` in step 5.
12. Class TEST in a `release` build: `TEST_SIGNER_IN_RELEASE`. A TEST-signed unit is never admitted by a release build, and a qualification build identifies itself in its boot report as ADR 0014 requires.
13. Signer lookup: the fingerprint must name a key in the anchor set of the unit's class (`UNTRUSTED_SIGNER`). The key is taken from the anchor set, never from the container.
14. Signature (`BAD_SIGNATURE`): the 32-byte scalar `S` (second half) must be below the group order `L` (RFC 8032 canonical form; the signature bytes are outside `UnitDigest`, so a non-canonical `S` would otherwise be a second valid file for one unit), then Ed25519 verification over `UnitDigest`.
15. Capability policy, three whole passes over all records, in this fixed order so one input has one first refusal: (a) every record's `domain` must be supported, else `CAP_DOMAIN_UNSUPPORTED`; (b) every domain-1 `required_generation` must fit 32 bits, else `CAP_GEN_NOT_REPRESENTABLE`; (c) every pinned generation must equal the loader's current generation of that resource, else `CAP_GENERATION_STALE`.
16. Resource reservation (`RESOURCE_UNAVAILABLE`); partial setup is forbidden and every failure releases everything (ADR 0014 section 5). The loader enforces its own hard maxima for stack, ticks, pool slots and pages; `max_stack_bytes`, `cpu_ticks` and `pool_slots` are signer-declared requests that can only lower what the loader would give, never raise it.

A unit that passes is admitted. The loader never executes the unit before this point. It does not recompile, verify the IR, or compare code against IR (section 10).

### 8.3 Refusal codes (v1 draft numbering; named, stable once frozen)

| Code | Name | Meaning |
|---:|---|---|
| 1 | `TRUNCATED` | file shorter than the header or than `total_length` |
| 2 | `BAD_MAGIC` | magic is not `OSCUNIT\0` |
| 3 | `CONTAINER_VERSION` | `container_version` not 1 |
| 4 | `HEADER_FIELD` | wrong `header_size`, table offset, section count or entry size, or a nonzero reserved byte |
| 5 | `UNIT_FORMAT` | `unit_format_version` not in the loader's supported set |
| 6 | `ABI_VERSION` | `runtime_abi_version` not provided by the loader |
| 7 | `UNKNOWN_FLAGS` | any `flags` bit set |
| 8 | `TRAILING_BYTES` | file longer than `total_length` |
| 9 | `TOTAL_LENGTH` | `total_length` outside 384 to 2,097,152 |
| 10 | `SECTION_TABLE` | wrong kind or order, nonzero flags or reserved |
| 11 | `SECTION_BOUNDS` | a section runs outside the permitted file range |
| 12 | `SECTION_OVERLAP` | two nonempty sections share bytes |
| 13 | `SECTION_LAYOUT` | non-canonical offset, nonzero gap, or section 4 not ending at the signature |
| 14 | `LIMIT_EXCEEDED` | a section 7 limit or declared-limit range violated (includes more than 32 functions) |
| 15 | `IR_HASH_MISMATCH` | IR bytes do not hash to the table value |
| 16 | `CODE_HASH_MISMATCH` | code bytes do not hash to the table value |
| 17 | `ENTRY_HASH_MISMATCH` | entry section hash mismatch |
| 18 | `CAPS_HASH_MISMATCH` | capability section hash mismatch |
| 19 | `IR_MALFORMED` | IR prefix or version byte wrong or different from the header |
| 20 | `ENTRY_TABLE` | entry record rule violated |
| 21 | `CAPS_TABLE` | capability record rule violated |
| 22 | `SIGNER_CLASS` | class not TEST or OWNER |
| 23 | `SIGNATURE_ALGORITHM` | algorithm not 1 |
| 24 | `TEST_SIGNER_IN_RELEASE` | class TEST in a release build |
| 25 | `UNTRUSTED_SIGNER` | fingerprint not in the anchor set of the unit's class |
| 26 | `BAD_SIGNATURE` | signature does not verify |
| 27 | `CAP_DOMAIN_UNSUPPORTED` | a request names a capability domain this loader does not provide |
| 28 | `CAP_GEN_NOT_REPRESENTABLE` | a generation cannot be represented in the request's domain |
| 29 | `CAP_GENERATION_STALE` | pinned generation differs from the resource's current generation |
| 30 | `RESOURCE_UNAVAILABLE` | reservation of pages, stack, task slot or capability slots failed |
| 31 | `ENTRY_NAME` | name length not 1 to 63, byte outside the charset, or nonzero padding |
| 32 | `ENTRY_NAME_HASH` | `name_hash` does not equal the hash of the carried name |
| 33 | `ENTRY_NAME_DUPLICATE` | two entry records carry the same name |
| 34 | `CODE_INSTRUCTION` | a code word outside the OSC-emitted instruction subset (section 8.4), or a `brk` whose immediate is not a trap code 1 to 14 |
| 40 | `LAUNCH_BAD_ENTRY` | `fn_index` not in the entry table, or no record's name equals the requested name exactly |
| 41 | `LAUNCH_ARG_SHAPE` | argument count, kind, slice pointer, length, alignment or overlap invalid (section 9.2) |

Numbers 35 to 39 and 42 to 255 are reserved. A loader receiving a code it does not know treats it as a failed admission.

### 8.4 Code scan: the instruction subset

Admission decodes every 32-bit word of CODE and refuses the unit (`CODE_INSTRUCTION`) if any word is not in the subset the OSC back end can emit. This is what makes "a unit makes no system calls of its own" a checked property instead of an attested one: no word that is a supervisor call (`SVC`), hypervisor call (`HVC`), secure monitor call (`SMC`), system register access (`MSR`, `MRS`), system instruction or barrier, load/store exclusive, FP/SIMD instruction or any other encoding outside the table can pass.

The allowed set is exactly the set of encodings that `osc_a64_decode` accepts (`src/compiler/osc_a64.c:28-72` operation table, `76-93` variable-field masks, decode at `245-274`): a word is allowed when, for some table entry, `word & ~varmask(class) == base` and re-encoding the decoded fields reproduces the word. The operations are `add/sub/adds/subs` (shifted register and immediate), `madd`, `msub`, `smulh`, `umulh`, `sdiv`, `udiv`, `lslv`, `lsrv`, `asrv`, `and`, `orr`, `eor`, `orn`, `sbfm`, `ubfm`, `csinc`, `movz`, `movn`, `movk`, `ldr` and `str` (64-bit unsigned offset), `stp` and `ldp` (offset, pre, post), `ldrb` (register), `b`, `bl`, `b.cond`, `cbz`, `cbnz`, `blr`, `ret`, and `brk`.

`brk` needs a rule of its own, because the compiler does emit it: after every call to the runtime trap service it places `brk #code` as an unreachable guard (`osc_cg.c:154-159`, `trap_seq`; `osc_rt_trap` does not return). A `brk` is allowed only when its 16-bit immediate is a trap code `1..=14`. Any other `brk` is refused. When the unit's execution actually reaches a `brk` it has faulted: the platform reports `OUTCOME_UNKNOWN` with reason `FAULT` (section 9.3), never `TRAPPED`.

Notes for implementers. The compiler's own decoder performs the round-trip check and is the reference. The vector checker in `tools/osc-unit-check.sh` implements the class-mask match only (it refuses every vector that the full rule refuses, but it is weaker than a loader must be). The scan is on the signed, hash-verified copy of the code. Allowing a word says nothing about what the code does; only that it cannot ask the platform for anything except through `OscRt` (`blr`) and cannot touch system state.

## 9. Launch and results

### 9.1 Calling convention (from `docs/osc/OSC-1-DESIGN.md` section 7)

Arguments in `x0..x5` in `reg_kind` order, a slice as two consecutive registers (pointer, length). The hidden runtime pointer `OscRt *` is in `x7`; the function's frame stores it in slot 0. Runtime services (allocation, release, traps, arenas, pools) are reached through `ldr x16, [x7 slot]` then the vtable then `blr x16`, at the fixed offsets of `runtime_abi_version` 1. The return value is one u64 in `x0` (bool as 0 or 1, narrower integers canonically extended). Calls between functions of the unit are `BL`. The launcher provides a stack of at least `max_stack_bytes`.

### 9.1.1 Launch requirements (the platform enforces these, the container cannot attest them)

1. **No system calls from unit context.** The platform refuses (never services) an `SVC` executed while unit code runs. The task that hosts unit code has an empty system-call mask except the single runtime entry the platform provides; a `SVC` from unit context terminates the activation as `OUTCOME_UNKNOWN` with reason `FAULT`. The capability table delivered to that task is exactly the granted subset of the CAPS section and nothing else. Section 8.4 is the first lock (no `SVC` word can be admitted); this is the second, independent lock.
2. **`OscRt` is not writable by the unit.** The runtime table `OscRt` (function pointers at offsets 0 to 96, `osc_rt.h:85-99`) and the runtime code it points to live outside memory the unit can write or address as data, either in a separate address space or behind a gate. The unit receives `x7` as an opaque pointer it may only pass back and call through; where the table is mapped into the unit's space it is read-only. `osc_rt.h` also embeds the cell pool next to the function pointers; a launcher MUST NOT give the unit a mapping in which writes to its pool arrays reach the function pointers. This is a launch blocker: a launcher that cannot satisfy it must not launch.
3. **The trap service does not return** into unit code. Reaching the `brk` guard after it is a fault (section 8.4).
4. **Ranges are the caller's.** Every `bytes` range must lie wholly in memory the caller may read, and be mapped read-only for the unit; every `cells` range wholly in memory the caller may write. Section 9.2 checks shape; this checks ownership (the host `osc_native.c` runs only the shape check).
5. **Platform limits.** The platform enforces its own stack, tick and page limits (section 8.2 step 16). Stack overflow, tick exhaustion and wild accesses surface as `OUTCOME_UNKNOWN` by design. `cpu_ticks` counts the AIENOS scheduler CPU ticks of the resource envelope in ADR 0014 section 2.4 (the unit is defined by AIENOS ABI v1, not here); a host adapter documents its own mapping. Worst-case stack use is not derivable from the container: a function frame is `8 * (nvregs + 1)` bytes rounded to 16 (up to 3856 for 480 virtual registers) plus 16 per call, nested up to the call depth the compiler permits, so `4096` is a minimum for declaration, not a safe value.

### 9.2 Argument checks before the first instruction

The launcher refuses `LAUNCH_ARG_SHAPE` unless every item holds. It is the rule of `osc_ir_slice_args_ok` (`osc_ir.c:689-705` at `d64ccb3`), restated exactly, plus the scalar rule:

1. The number of argument registers equals `nregs` (a slice counts two).
2. Each scalar register fits its kind: bool 0 or 1; u8, u16, u32 within their range; i8, i16, i32 are the canonical sign extension of the value in 64 bits (so `0xffffffffffffff80` is a valid i8, `0x80` is not).
3. For each slice, with pointer `ptr` and length `n` taken from its two registers, and `size = n` for `bytes` and `size = n * 8` for `cells` (computed in 64 bits):
   a. for `cells`, `n` must not exceed `UINT64_MAX / 8` (so `n * 8` cannot wrap), and if `n` is nonzero `ptr` must be 8-byte aligned;
   b. if `n` is nonzero, `ptr` must be nonnull; a zero length with a null pointer is allowed and the pointer is never dereferenced;
   c. `size` must not exceed `UINT64_MAX - ptr` (the range must not wrap).
4. Overlap, over every ordered pair of distinct slices `p`, `q`: two `bytes` ranges may overlap each other freely. Any pair in which at least one is `cells` is refused if their ranges `[ptr, ptr + size)` intersect. A pair is skipped when either `size` is zero (a zero-length range overlaps nothing), or when the other slice's own size computation would wrap; that other slice is refused by item 3 on its own turn.

Borrows last for that one call; the runtime keeps no reference. The vectors in `vectors/launch.txt` exercise each item.

### 9.3 Result shape

Every admission-and-launch attempt ends in exactly one of four result classes. The classes are closed: a new reason or detail never creates a fifth class.

- `RETURNED(value u64)`: the entry function returned. `value` is `x0`. A void function reports 0.
- `TRAPPED(trap_code u8)`: the unit called the runtime trap service with a code in `1..=14` (`OVERFLOW` 1, `DIV0` 2, `BOUNDS` 3, `LOOP_BOUND` 4, `CAST` 5, `OOM` 6, `SHIFT` 7, `RUNTIME` 8, `REQUIRES` 9, `ENSURES` 10, `ARENA_FULL` 11, `STALE` 12, `POOL_FULL` 13, `RETIRED` 14, the table `OSC_TRAP_*` at `osc_ir.h:151-170` of `d64ccb3`; `OSC_TRAP_MAX` is 14). A launcher accepts any code in `1..=14` for every unit format: the runtime table is shared by all formats of `runtime_abi_version` 1, and a unit of an older format simply never raises the newer codes). Traps are numbered results, never process exit. The launcher unwinds the call and releases the unit's runtime state; no further unit instruction runs.
- `REFUSED_AT_ADMISSION(code)`: any code of section 8.3; no unit instruction ran.
- `OUTCOME_UNKNOWN`: unit instructions started and neither a return nor a numbered trap was observed. Examples (each has an `unknown_reason`): `cpu_ticks` exhausted, a CPU fault in the unit (stack overflow, wild access), the task destroyed or the machine reset mid-run, or a trap code outside the table for the unit's format. A caller MUST NOT retry on `OUTCOME_UNKNOWN` as if nothing happened (same rule as OSH Platform ABI section 10). It carries a fixed-width `unknown_reason` (u8), see below.

A trap code of 0 is not a trap. A launcher never maps a fault to `TRAPPED`.

**`unknown_reason`** (present only with `OUTCOME_UNKNOWN`, u8): `1` `FAULT` (CPU fault in the unit), `2` `TICK_OVERRUN` (`cpu_ticks` exhausted), `3` `LAUNCH_LOST` (task destroyed, machine reset or launcher lost contact), `4` `TRAP_CODE_UNKNOWN` (trap code outside the table for the unit's format), `255` `OTHER`. Value `0` is not used with `OUTCOME_UNKNOWN`; a consumer that sees a value it does not know treats it as `255`. The field is diagnostic only: it carries no authority, never changes the result class, and a caller must not branch semantics on it (in particular, no reason makes a retry safe). Resumable budget exhaustion in a caller such as the OSH core is that caller's own status, never a launch result.

## 10. What the signature does and does not prove

The code is bound to the IR only by the signer's attestation. The loader checks that the IR bytes and code bytes hash to the values the signer signed, and that the signer is trusted. It does not recompile the IR, does not verify the IR, does not check that the code implements the IR, and does not check that the entry table, function count or limits describe the code. A TEST or OWNER signer who signs a mismatched pair makes a valid container of mismatched content. The IR travels so that a verifier, the producer's evidence, or a later in-kernel checker can compare; the kernel does not in v1.

What the container does prove: these exact bytes, in this exact table, were signed by a key in the loader's anchor set for the stated class.

## 11. Security considerations

- Parsing happens on a private copy of the bytes. Hashing and signature checks use that copy, and the loader hashes again after copy into code pages (no time-of-check to time-of-use gap).
- Fail closed: the production OWNER and TEST anchor sets are empty until provisioned. A release build has no TEST anchor and refuses class TEST before looking at the signature.
- The class label, fingerprint and algorithm are signed, so a TEST container cannot be relabelled OWNER and an algorithm cannot be downgraded without invalidating the signature.
- The key never comes from the container. A fingerprint only selects among local anchors.
- Domain separation tags make a signature on a unit unusable as an ADR 0014 artifact signature or a receipt signature.
- No revocation, rollback protection or version monotonicity exists in v1. A validly signed old unit stays admissible while its signer is trusted. Revocation is trust-anchor policy (open item).
- Machine code runs in an isolated EL0 task with only the runtime services and the capabilities admission grants. The container does not sandbox; the isolation is the loader's (ADR 0013, 0014). Two locks stop a unit from using system calls: admission refuses every code word outside the OSC-emitted subset (section 8.4), and the platform refuses `SVC` from unit context (section 9.1.1). The runtime table is not writable by the unit (section 9.1.1 item 2): a unit that could overwrite `trap` or `alloc` would run its own code in the runtime context.
- An unsound signer is outside the model. The IR is not checked against the code (section 10), so the signer's key custody is the root of trust for what the code does.
- Throwaway keys in the vectors protect nothing and must never be added to any anchor set of a real build.

## 12. Out of scope

GPU code and GPU loading; recursion (OSC has none); dynamic linking, relocations, imports between units; a data section; persisting or migrating a running unit; the 64-bit to 32-bit generation bridge; delegation chains from the Owner Root (ADR 0017); revocation lists; the Admission Receipt amendment; how the OSC runtime host (the provider of `OscRt`) is built and admitted on AIENOS.

## 13. Open items before freeze

1. Answered by the OSH owner (ee6210, aien-protocols#17 review comment) and applied in this draft: (a) four result classes kept, `unknown_reason` added as a diagnostic only (section 9.3); (b) bounded exact-match names carried, hash is an index only (section 6.1.1); (c) execution and authorization bind to `UnitDigest`, `ir_sha256` is program identity only (section 5.2). The line-by-line review from the OSH owner is still pending; nothing here is frozen.
2. `OscRt` vtable offsets are fixed by `runtime_abi_version` 1. Confirmed by the OSH owner: `src/compiler/osc_rt.h` and `osc_rt.c` are byte-identical between omega `main` and the OSC-EXT-BYTES head `d64ccb3` (empty `git diff`), so OSC-EXT-BYTES does not change the runtime table (`osc_rt.h:85-99`, offsets 0 to 96). Any future change to it bumps `runtime_abi_version`, and unknown versions are refused.
3. How AIENOS hosts `OscRt`: a Binary Artifact v0 task that receives the unit, or a new admission path. This spec does not choose.
4. Whether the loader should cross-check `function_count` against the IR (needs parsing the struct table) in v2.
5. OWNER delegation from the TRUST-1 Owner Root (ADR 0017) and revocation.
6. The numbering in section 8.3 freezes with the container.
7. Expected verdicts in `vectors/` were produced by the shell generator and judged by the shell checker and a small C reference written from this text. No kernel or adapter loader has run them. The shell checker implements the instruction subset as a mask match only (section 8.4).
8. Resolved by the line review (OSH owner, review of 1e49b3f, later commits): launch-argument rule restated exactly after `osc_ir_slice_args_ok` (9.2); one fixed capability-policy order (8.2 step 15); instruction subset and the `SVC` and `OscRt` launch locks (8.4, 9.1.1); entry kinds 11 and 12 need unit format 5; equal `name_hash` refused; canonical signature `S < L`; signer class and algorithm checked before hashing; length mismatches of ENTRY and CAPS are `ENTRY_TABLE` and `CAPS_TABLE`; `pool_slots` and `cpu_ticks` defined.
9. Found while fixing the review: the compiler emits `brk #trapcode` after every trap call (`osc_cg.c:154-159`), so `brk` cannot be banned outright as the review suggested; it is allowed only with an immediate of 1 to 14.

## 14. Conformance

A loader conforms when, for every line of `vectors/expected.txt`, run in the stated mode, with the stated capability domains and anchors, it returns the stated verdict: `ACCEPT` with `unit_digest` equal to `UnitDigest` of section 5.1 and `program_id` equal to the IR section hash, or `REFUSED` with that name and number. Anchors: `T` the TEST key in `keys/test1.pub` is the TEST anchor, `O` the key in `keys/owner1.pub` is the OWNER anchor, `-` neither. Both keys are throwaway TEST keys derived from fixed labels in `tools/make-vectors.sh`. `vectors/lookups.txt` lists name lookups on an admitted unit: the exact name returns its `fn_index`, anything else (including a different case or prefix) is `LAUNCH_BAD_ENTRY`; an implementation must not select a function by `name_hash` alone.

`tools/check-vectors.sh` regenerates the vectors into a scratch directory, requires them byte-identical to the committed ones, then runs: the reference checker over every line of `expected.txt` (counts in `vectors/README.md`), `lookups.txt` (exact-name lookups), `state.txt` (admission codes 29 and 30, which need loader state, supplied as scenario input), and `tools/osc-launch-check.c` over `launch.txt` (launch code 41, a dynamic rule that has no static container; launch code 40 is exercised by `lookups.txt` and, for an out-of-range `fn_index`, is a loader-side scenario with no byte vector). Requires bash, xxd, sha256sum, bc, a C99 compiler and OpenSSL 3 with Ed25519. The shell checker implements the instruction subset as a class-mask match; the normative rule (section 8.4) adds the decoder round trip, which the shell checker does not.

The vector unit is `src/min.osc` compiled by omega `oscc` at `d64ccb3`: `ir_sha256=084803c232dc44effcc44704c9ed0600dec1231451e0b76693633e98a48d1a1d`, `code_sha256=6163612fd91c0ce8eb8126d4b38534867428704d346795a5e369055eef10fcdb`, `funcs=2`, IR version byte 5 (it uses a `bytes` parameter). Its code ends with a `brk #3` trap guard, which section 8.4 permits.
