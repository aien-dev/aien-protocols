# Execution Transcript: TRN1

**Status**: Draft v0 (hardening lane LB, 2026-10-01); 0.2.0 adds the causal and resource records (hardening cut S1, lane HD-08, 2026-10-01). Not yet produced by any runtime.
**Contract version**: 0.2.0 (major zero: may change by minor bump, see VERSIONING.md)
**Wire schema versions**: 1 (contract 0.1 record registry) and 3 (contract 0.2 record registry), in the `schema` field below; rule in section 10
**0.2.0 sources**: aien-architecture `docs/hardening/causal-id-join-v0.md` (merged `fa46a26`: sections 2.1, 3.1 to 3.3, 3.5, 4) and `docs/hardening/resource-contract-v0.md` (merged `ddc17b7`: section 4)
**License**: Community Specification License 1.0
**Reference verifier**: [`tools/trn1_verify.c`](tools/trn1_verify.c), C99, self-contained (own SHA-256, libc only)
**Planned implementations**: omega `tools/replay` (C verifier and replayer, lane LD); sovereign-core `crates/aien-replay` (Rust reader, lane LE)
**Conformance corpus**: [`vectors/`](vectors/) with [`vectors/expected.txt`](vectors/expected.txt) and [`vectors/compare.txt`](vectors/compare.txt)

## 1. Purpose

A run of an AIEN system makes choices that are not fixed by its inputs: which
reaction the scheduler wakes next, which branch id it hands out, which random
seed it draws, what an outside source sent, which capability generation was
current. A TRN1 transcript writes those choices down, in order, so that:

1. a **verifier** can tell, from the bytes alone, whether a transcript is
   complete and undamaged (nothing dropped, reordered, flipped or cut off);
2. a **replayer** can run the same program again, feed it the recorded
   choices, write a second transcript, and **compare** the two record by
   record, reporting `MATCH through N` or the first divergence.

The transcript is the byte format and the outcomes, never a language type.
No C struct, Rust enum or serialization crosses it.

What is deliberately **not** in the compared part of a transcript: wall-clock
times, worker or core placement, and anything else that may differ between
two correct runs of the same history. Those may be kept as *annotations*
(section 4.3), which are integrity-protected but never compared.

## 2. Verifier and comparison interface

A verifier is a pure function of one read-only byte buffer. It returns
exactly one of:

- **accept**, with the record count, the run id and the final chain digest
  (section 7), or
- **refuse**, with one refusal code (section 6) and the 1-based position of
  the record where the first failing check fired (0 = the file header).

A comparison takes two buffers, *expected* (the recorded run) and *actual*
(the replay), verifies both, and returns one line (section 8).

Neither performs I/O beyond reading its input, reads clocks, or uses
randomness that can change the outcome.

## 3. File header (48 bytes)

All integers are unsigned little-endian unless marked signed (two's
complement). Offsets are from the start of the buffer.

| Offset | Size | Field | Valid values |
|---|---|---|---|
| 0 | 4 | magic | ASCII `TRN1` (`54 52 4E 31`) |
| 4 | 2 | schema | `1` or `3` (section 10); every other value is refused |
| 6 | 2 | flags | `0` (no flags defined) |
| 8 | 32 | run_id | opaque; the root causal id of this run (plan item P5). Any value. |
| 40 | 2 | producer | subsystem id (section 5.2) of the writer; not 0 |
| 42 | 6 | reserved | all zero |

The **header digest** is SHA-256 over these 48 bytes. It is the `prev` value
of record 1.

## 4. Records

### 4.1 Record layout

After the header come one or more records, back to back. The last record is
always `END` (type `0xFFFF`), and nothing follows it.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 2 | type | a known record type (section 5.1) |
| 2 | 2 | subsystem | a known subsystem id (section 5.2); 0 on `END` and only on `END` |
| 4 | 4 | ident_len | identity length, at most 65536, exact per type |
| 8 | 4 | annot_len | annotation length, at most 65536; 0 on `END` |
| 12 | 4 | reserved | zero |
| 16 | 8 | seq | position of this record, 1-based, dense: record k has seq k |
| 24 | 32 | prev | record digest of record k-1, or the header digest for k = 1 |
| 56 | ident_len | identity | type-specific, compared on replay (section 5.1) |
| 56 + ident_len | annot_len | annotation | opaque, chained, never compared |

### 4.2 Two digests per record

- **Record digest** = SHA-256 over the whole record, bytes 0 through the end
  of the annotation. It goes into the next record's `prev`, so the records
  form a hash chain anchored on the header. The record digest of `END` is the
  **final digest** of the transcript; publishing it (for example in a
  receipt) pins the whole file.
- **Compared digest** = SHA-256 over
  `"AIEN_TRN1_CMP"` (13 ASCII bytes) `|| type (2) || subsystem (2) || seq (8) || ident_len (4) || identity`,
  all integers little-endian. Comparison (section 8) uses only this. It leaves
  out `prev`, the annotation and the header, so two runs of the same history
  with different run ids, timings or worker placement compare equal.

### 4.3 Identity versus annotation

Everything that a correct replay must reproduce goes in the identity.
Everything that may legitimately differ between two correct runs goes in the
annotation. Writers must not put a wall-clock value in an identity unless the
program's behaviour depended on it, and then it is a `CLOCK_READ` record.

## 5. Registries

### 5.1 Record types

`ident` lengths are exact unless stated. "digest" fields are 32 bytes.
Fields named `reserved` must be zero (NONCANONICAL otherwise).

| Type | Name | ident_len | Identity fields in order |
|---|---|---|---|
| 1 | SCHED_DECISION | 32 | decision u64 (logical step), chosen u64 (task or reaction id), wake_cause u64, coalesced u64 |
| 2 | BRANCH_CREATE | 24 | branch u64 (logical id), parent u64 (0 = root), generation u64 |
| 3 | BRANCH_DESTROY | 24 | branch u64, generation u64, reason i32, reserved u32 |
| 4 | RNG_SEED | 40 | stream u64, seed[32] |
| 5 | RNG_DRAW | 24 | stream u64, index u64, value u64 |
| 6 | ARTIFACT_DIGEST | 48 | kind u32, reserved u32, artifact u64, digest |
| 7 | CAP_TRANSITION | 32 | cap_id u32, op u8 (1 MINT, 2 ATTENUATE, 3 TRANSFER, 4 REVOKE, 5 RECLAIM, 6 EPOCH; else SHAPE), reserved[3], generation_before u64, generation_after u64, principal u32, issuer u32 |
| 8 | CORTEX_READ | 56 | object u32, object_generation u32, version u64, mask u64, value digest |
| 9 | EFFECT_INTENT | 56 | effect u64, effect_class u32, cap_id u32, cap_generation u64, request digest |
| 10 | EFFECT_COMMIT | 48 | effect u64, outcome i32, reserved u32, result digest |
| 11 | EXTERNAL_INPUT | 48 to 4144 | source u32, reserved u32, input_seq u64, content digest, content (0 to 4096 bytes). When content is present its SHA-256 must equal the digest (DIGEST otherwise); when absent the content is stored elsewhere and only the digest is pinned. |
| 12 | CLOCK_READ | 16 | clock u32, reserved u32, value u64. Only for reads the program's behaviour depended on. |
| 13 | CRASH_BOUNDARY | 48 | epoch u64, last_durable_seq u64 (must be below this record's seq, SHAPE otherwise), recovered state digest |
| 14 | CHECKPOINT | 40 | scope u32, reserved u32, subsystem state digest |
| 15 | RX_CRUMB | 32 + n | crumb digest, then the canonical crumb bytes (section 5.3) |
| 16 | ARGUS_EVENT | 200 | event[128], chained u8 (0 or 1, SHAPE otherwise), reserved[7], chain_before digest, chain_after digest (section 5.4) |
| 17 | CAUSE | 80 | schema 3 only: cause[32], mode u32, local_kind u32, local u64, root digest (section 5.5) |
| 18 | RECEIPT_BIND | 40 | schema 3 only: cause[32], format u32, reserved u32 (section 5.5) |
| 19 | RUN_LINK | 48 | schema 3 only: relation u32, reserved u32, parent branch u64, parent create digest (section 5.5) |
| 20 | TRAIN_DISPATCH | none | number reserved; no layout in 0.2.0, so refused as UNKNOWN under every schema (section 5.5) |
| 21 | RESOURCE | 96 | schema 3 only: op u8, reason u8, field u16, reserved u32, unit u64, cause[32], contract digest, declared u64, used u64 (section 5.5) |
| 0xFFFF | END | 16 | record_count u64 (must equal this record's seq, GAP otherwise), reserved u64 |

Under schema 1 the registry is types 1 to 16 and END; types 17 to 21 are
unknown there and refused with UNKNOWN (vectors `m030`, `m070`).

### 5.2 Subsystems

| Id | Name | Id | Name |
|---|---|---|---|
| 0 | transcript (END only) | 6 | aienos-store |
| 1 | omega-world | 7 | sovcore-runtime |
| 2 | omega-cortex | 8 | sovcore-scheduler |
| 3 | omega-jspace | 9 | sovcore-kv |
| 4 | aienos-kernel | 10 | external |
| 5 | aienos-argus | | |

The name column is the text printed in a DIVERGENCE line.

### 5.3 RX_CRUMB: carrying an Omega RxCrumb without loss

Source of truth: omega `src/runtime/rx_world.h` (`RxCrumb`) and
`src/runtime/rx_world.c` (`crumb_hash`), checked at omega main `9ca297c`.
Omega computes a crumb's digest as SHA-256 over the ASCII tag
`AIEN_RX_CAUSAL_V1` (17 bytes) followed by these little-endian fields; the
**canonical crumb bytes** in a TRN1 record are exactly those fields, without
the tag:

| Field | Size |
|---|---|
| id | u64 |
| kind | u32 (`RxCrumbKind`; not range-checked here, so new kinds pass) |
| reaction | u32 (`UINT32_MAX` for external or create) |
| faculty | u32 |
| wake_cause | u64 |
| coalesced_wakes | u64 |
| n_inputs, then n_inputs times (obj id u32, obj generation u32, version u64, mask u64) | u32 + 24 each, n_inputs at most 8 |
| n_caps, then n_caps times (cap_id u32, generation u64, issuer u32) | u32 + 16 each, at most 8 |
| n_outputs, then n_outputs times (obj id u32, obj generation u32, version u64, mask u64) | u32 + 24 each, at most 8 |
| reason | i32 |
| n_parents, then n_parents times (parent u64, then the parent's 32-byte digest **only if 1 <= parent < id**) | u32 + 8 or 40 each, at most 65 |

The bytes must parse to exactly their length (SHAPE otherwise), and the
first 32 bytes of the identity must equal
SHA-256(`AIEN_RX_CAUSAL_V1` || canonical bytes) (DIGEST otherwise). Limits 8,
8, 8 and 65 are omega's `RX_MAX_DEPS`, `RX_MAX_CAPS`, `RX_MAX_WRITES` and
`RX_MAX_PARENTS` (= 8 * 8 + 1).

The fields omega keeps but does not hash (`worker`, `t_start_ns`, `t_end_ns`,
`episode`) are not identity. A writer that wants them kept puts them in the
annotation as `worker u32, t_start_ns u64, t_end_ns u64, episode u64`
(28 bytes); the corpus does this. With that annotation every `RxCrumb` field
is carried, and the omega digest is carried and rechecked unchanged: the
conversion is lossless and needs no omega code. Omega's rule "a parent
digest is hashed only when the parent precedes the child" is reproduced by
the `1 <= parent < id` rule above (vector `p002` exercises parents 0 and
parents at or above the crumb id).

### 5.4 ARGUS_EVENT: carrying the AIENOS ARGUS chain without loss

Source of truth: aienos `native/argus/argus_abi.h` and `argus_event.c`
(`encode_raw`, `argus_chain_extend`), and `argus_core.c` (chain starts from
32 zero bytes; malformed events are recorded but not chained), checked at
aienos main `33927b1`.

- `event` is the 128-byte ARGUS wire encoding exactly as `argus_event_encode`
  writes it (ABI version 1). TRN1 does not validate ARGUS semantics; that is
  the ARGUS decoder's job.
- `chained = 1`: `chain_after` must equal SHA-256(`chain_before` || `event`),
  which is what `argus_chain_extend` computes. `chained = 0`: `chain_after`
  must equal `chain_before`.
- Continuity: inside one transcript, each ARGUS_EVENT's `chain_before` must
  equal the previous ARGUS_EVENT's `chain_after`. The first ARGUS_EVENT may
  start from any value (all zeros for a stream that starts at boot), so a
  transcript can begin in the middle of a run. Failures are DIGEST.

The ARGUS `tick` field is the authority's logical clock, not a wall clock,
and stays in the identity.

### 5.5 Causal and resource records (contract 0.2.0, schema 3 only)

Source of truth: aien-architecture `docs/hardening/causal-id-join-v0.md`
(merged `fa46a26`) sections 2.1, 3.1 to 3.3 and 3.5 (the joint number
table), and `docs/hardening/resource-contract-v0.md` (merged `ddc17b7`)
section 4, with the 32-byte cause required by causal-id-join section 3.5.
All integers little-endian; "digest" is 32 bytes. These types exist only in
a file whose header schema is 3; under schema 1 they are UNKNOWN.

**Cause id.** A 32-byte value,
`SHA-256("AIEN_CAUSE_V0" (13 ASCII bytes) || subsystem u16 || local_kind u32 || local u64 || root digest)`,
minted once where an outside input enters AIEN and copied, never re-minted,
downstream (causal-id-join section 2.1 and 2.3). A TRN1 verifier carries it;
it does not recompute it (see "Verifier rules versus join rules" below).

**Type 17 CAUSE (80 bytes).**

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 32 | cause | the cause id |
| 32 | 4 | mode | 1 MINT, 2 ADOPT, 3 REF; else SHAPE |
| 36 | 4 | local_kind | 1 omega episode, 2 aienos admission, 3 sovcore request, 4 train run (causal-id-join table 2.2 and section 3.4). MINT and ADOPT: 1 to 4, else SHAPE. REF: 0 to 4, else SHAPE |
| 40 | 8 | local | MINT and ADOPT: not 0, else SHAPE. REF: any |
| 48 | 32 | root digest | MINT: the digest the cause was minted over. ADOPT and REF: all zero, else NONCANONICAL |

Annotation (never compared, not checked by the verifier): an ADOPT carries
origin run id (32) then origin seq (u64).

**Type 18 RECEIPT_BIND (40 bytes).**

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 32 | cause | a cause opened earlier in this run (a join rule, below) |
| 32 | 4 | format | 1 aienos `cka_receipt`, 2 omega evidence receipt, 3 sovereign-core `aien-proof`; else SHAPE |
| 36 | 4 | reserved | zero, else NONCANONICAL |

Annotation: the receipt digest (32). It is chained but never compared,
because receipt bytes may differ between correct runs (vector `g008`
MATCHes `g006` with a different receipt digest).

**Type 19 RUN_LINK (48 bytes).** Allowed only as record 1 (SHAPE otherwise).

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 4 | relation | 1 CHILD_OF; else SHAPE |
| 4 | 4 | reserved | zero, else NONCANONICAL |
| 8 | 8 | parent branch | the `branch` of the parent's `BRANCH_CREATE` |
| 16 | 32 | parent create digest | the compared digest (section 4.2) of that `BRANCH_CREATE` record |

Annotation: parent run id (32) then parent seq (u64).

**Type 20 TRAIN_DISPATCH.** The number is reserved by the joint table
(causal-id-join section 3.5). Its identity layout is not fixed in 0.2.0, so
every reader refuses type 20 as UNKNOWN (vector `m071`). A later minor
version defines it.

**Type 21 RESOURCE (96 bytes).**

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 1 | op | 1 CHARGE, 2 REFUND, 3 REFUSE, 4 CANCEL, 5 OVERRUN, 6 OVER_OBSERVED; else SHAPE |
| 1 | 1 | reason | REFUSE: 1 BUSY, 2 OVER_BUDGET, 3 UNKNOWN, 4 QUOTA. CANCEL: 1 DEADLINE, 2 PARENT, 3 EXPLICIT. Every other op: 0. Else SHAPE |
| 2 | 2 | field | contract field number 1 to 10 (resource-contract section 1.2), or 0 for a whole-need charge or refund; above 10 SHAPE |
| 4 | 4 | reserved | zero, else NONCANONICAL |
| 8 | 8 | unit | the reaction or task id the outcome applies to |
| 16 | 32 | cause | the cause id this outcome serves |
| 48 | 32 | contract | digest of the contract record in force |
| 80 | 8 | declared | the declared limit for `field` (0 when absent) |
| 88 | 8 | used | the deterministic amount used, 0 for a measured field |

Measured amounts (CPU, wall, GPU, energy) go in the annotation, never the
identity (resource-contract section 4). The 8-byte cause of the first
arch#96 draft is refused by length (vector `m073`).

**Verifier rules versus join rules.** A TRN1 verifier checks the rules in
the tables above, one file at a time, with the refusal codes of section 6.
It does **not** check: that a minted cause recomputes, that a cause is
minted once, CAUSE placement and adjacency, that a RESOURCE or RECEIPT_BIND
names a cause opened earlier in the run, that an effect or branch is
preceded by a CAUSE REF, ADOPT origins, RUN_LINK parents, or receipt
contents. Those are steps 3 to 10 of the causal join (causal-id-join section
4), which has its own outcome line and codes (`CAUSE_DIGEST`, `REF_UNKNOWN`
and the rest), and some of which need more than one file (a child run's
causes are opened by its parent). A transcript that breaks only a join rule
**verifies**; the corpus lists the join refusals it expects in
`vectors/join.txt` (section 9).

## 6. Refusal codes

Zero means accept. A refusal is a negative integer from this table, and only
from this table.

| Code | Name | Meaning |
|---|---|---|
| -1 | MAGIC | first four bytes are not `TRN1` |
| -2 | VERSION | schema is not 1 or 3 (unknown version, older or newer; section 10) |
| -3 | LENGTH | buffer ends inside the header or a record; a length above its limit; bytes after END |
| -4 | NONCANONICAL | a flag or reserved field is not zero |
| -5 | UNKNOWN | unknown record type, unknown subsystem, or producer 0 or unknown |
| -6 | SHAPE | identity length wrong for its type; a field outside its valid set; END subsystem or annotation rule broken; malformed crumb bytes |
| -7 | GAP | a record's seq is not its position (omission, reorder, duplicate) or END's record_count differs from its seq |
| -8 | CHAIN | a record's prev is not the digest of what precedes it (bit flip, splice) |
| -9 | DIGEST | an embedded digest does not match: crumb digest, external input content, ARGUS chain link or continuity |
| -10 | TRUNCATED | the buffer ends cleanly after a record that is not END |

## 7. Check order (determines the code)

A verifier refuses with the code of the **first** failing check, in this
order. "event" is the position k of the record being checked (0 = header).

Header:

1. Fewer than 4 bytes: LENGTH. Magic not `TRN1`: MAGIC.
2. Fewer than 6 bytes: LENGTH. schema not 1 and not 3: VERSION.
3. Fewer than 48 bytes: LENGTH. flags not 0: NONCANONICAL.
4. producer 0 or unknown: UNKNOWN.
5. reserved not zero: NONCANONICAL.

Then for record k = 1, 2, ...:

1. Buffer ends exactly here: TRUNCATED. Fewer than 56 bytes left, or k above 4096: LENGTH.
2. type unknown for the file's schema (types 17 to 21 under schema 1, type 20
   under every schema): UNKNOWN. subsystem unknown: UNKNOWN.
3. reserved not zero: NONCANONICAL.
4. ident_len or annot_len above 65536: LENGTH.
5. seq not k: GAP.
6. prev not the previous digest: CHAIN.
7. identity plus annotation not fully present: LENGTH.
8. Shape, in this order: ident_len rule for the type; END-and-only-END has
   subsystem 0; CAP_TRANSITION op; CRASH_BOUNDARY last_durable_seq < k;
   RX_CRUMB canonical bytes; ARGUS_EVENT chained flag; END annot_len 0;
   then (schema 3) CAUSE mode, CAUSE local_kind, CAUSE local, RECEIPT_BIND
   format, RUN_LINK relation, RUN_LINK is record 1, RESOURCE op, RESOURCE
   reason, RESOURCE field. Any failure: SHAPE.
9. Reserved fields inside the identity, then (schema 3) CAUSE root digest
   zero for ADOPT and REF, RECEIPT_BIND reserved, RUN_LINK reserved,
   RESOURCE reserved: NONCANONICAL.
10. Embedded digests: RX_CRUMB digest, EXTERNAL_INPUT content, ARGUS
    continuity then ARGUS link. Any failure: DIGEST.
11. If END: record_count not k: GAP. Bytes remain after END: LENGTH with
    event k + 1. Otherwise accept.

The 4096-record cap is a limit of this v0 reference verifier and corpus, not
a property of the format; a later contract version may lift it.

## 8. Outcome lines and comparison

Every outcome is one canonical text line, which is also the corpus manifest
format.

Verify:

```text
ok records=N run=<run_id, 64 hex> final=<final digest, 64 hex>
refuse CODE event=K
```

Compare (expected first, actual second): both are verified first. If one is
refused the line is `refuse expected CODE event=K` or
`refuse actual CODE event=K` (expected checked first). Otherwise the
compared digests (section 4.2) are compared position by position from 1:

```text
MATCH through N
DIVERGENCE event=K expected=<compared digest, 64 hex> actual=<compared digest, 64 hex> subsystem=<name>
```

`subsystem` names the expected record's subsystem (section 5.2). Because
every transcript ends with END, whose identity holds the record count, two
transcripts of different length always diverge at or before the shorter
one's END; `MATCH through N` therefore means both have exactly N records with
equal identities.

What a chain does and does not prove: the chain catches accidental damage
and naive tampering in one file. A writer that drops a record and then
renumbers and rechains produces a transcript that verifies (corpus `f001`).
That is caught only by comparison with a replay, or by checking the final
digest against an independently stored copy. Consumers must not treat
"verifies" as "is the history that happened".

## 9. Conformance corpus

`vectors/expected.txt` lists every transcript as `<file> <verify line>`;
`vectors/compare.txt` lists pairs as `<expected> <actual> <compare line>`;
`vectors/join.txt` lists `<file> JOIN_REFUSED reason=<CODE> run=<64 hex> event=<k>`
for transcripts that verify but that the causal join (section 5.5) must
refuse, the join set being that one file. The reference verifier does not
read `join.txt`; it is input for a joiner, and NOT_RUN until one checks it.
Lines starting with `#` are comments. Plain text, so C, shell, Rust and
Omega harnesses can read them without a JSON parser.

| Group | Files | What it shows |
|---|---|---|
| Golden | `g001` .. `g005` | g001 an Omega World run (two real RxCrumbs, effect intent and commit); g002 an ARGUS stream (two chained events, one unchained); g003 every other record type, including a crash boundary; g004 END only; g005 a replay of g001 with a different run id, workers and timings, which MATCHes g001 |
| Edge positives | `p001`, `p002` | 4096-byte external input with a large annotation; a crumb at omega's 8/8/8 limits with digest-less parents |
| Forged replays | `f001` .. `f006` | valid chains with a different history: omission, reorder, changed seed, changed capability generation inside a crumb, extra record, early stop. Each verifies alone and DIVERGEs from g001 at the named record |
| Byte damage | `m001` .. `m018` | g001 damaged after writing: omission, reorder, bit flips (identity, annotation, prev, seq, run id, magic, crumb bytes, END), truncation (header, mid record, inside END, at a record boundary), empty file, trailing byte, duplicate |
| Built refusals | `m020` .. `m065` | rechained so only the named check can fire: unknown versions (2 and 0), flags, producer, reserved fields, unknown type and subsystem, check order cases, oversize identity, every SHAPE rule, every DIGEST rule including an omitted ARGUS event the writer rechained |
| 0.2 golden | `g006` .. `g008` | schema 3. g006 one sovcore request start to receipt: CAUSE MINT, RESOURCE charge, CAUSE REF before a branch and before an effect, refund, RECEIPT_BIND; g007 a child run (RUN_LINK as record 1 naming g006's BRANCH_CREATE, CAUSE ADOPT, RESOURCE cancel); g008 a replay of g006 with another run id and receipt digest, which MATCHes g006 |
| 0.2 edge positive | `p003` | top of each range: local_kind 4, REFUSE reason 4, CANCEL reason 3, OVERRUN, OVER_OBSERVED on field 10, receipt format 1 |
| 0.2 forged | `f007` .. `f009` | rechained: cause bit flip in a RESOURCE, RESOURCE before its MINT (reorder), MINT omitted before the RESOURCE. Each verifies and DIVERGEs from g006 |
| Join only | `j001` .. `j005` | verify under TRN1; `join.txt` names the join refusal: CAUSE_DIGEST, DOUBLE_MINT, REF_MISSING, COMMIT_ORPHAN, RECEIPT_CAUSE (f007 and f009 are listed there too, REF_UNKNOWN) |
| 0.2 refusals | `m070` .. `m092` | a valid 0.2 record under a schema 1 header (UNKNOWN); type 20 (UNKNOWN); wrong lengths (CAUSE 79 bytes, RESOURCE with the old 8-byte cause); every 0.2 SHAPE and NONCANONICAL rule; a check-order case; byte damage on g006 (cause bit flip, reorder) |

Regenerate with `tools/make-corpus.sh vectors`. The generator is shell plus
coreutils (`sha256sum`, `od`, `sed`) and builds every byte from the tables
above; it never calls the verifier. `tools/check-corpus.sh` regenerates the
corpus into a temporary directory and requires it byte-identical to
`vectors/`, then builds the reference verifier (warnings as errors, and an
ASan/UBSan build when available) and checks every line.
`tools/mutate-verifier.sh` builds one verifier per check with that check
disabled and requires the corpus to catch each one (no survivors).

A conforming harness prints one summary line:

```text
TRN1_CONFORMANCE impl=<c|rust|osc|...> pass=N fail=0
```

## 10. Versioning

- The header `schema` names the record registry in force. Schema 1: contract
  0.1 registry (types 1 to 16 and END). Schema 3: contract 0.2 registry
  (schema 1 plus types 17, 18, 19, 21). Schema 2 is never assigned: vector
  `m020` has pinned it as an unknown schema since 0.1.0, and existing
  vectors keep their outcomes.
- Version negotiation is by the header only. A reader accepts exactly the
  schemas it implements and refuses every other value with VERSION at event
  0; it never reinterprets an older or newer file. So a 0.1 reader refuses a
  schema 3 file cleanly (VERSION, event 0), and a 0.2 reader refuses a
  0.2 record inside a schema 1 file (UNKNOWN at that record, vector `m070`).
  A 0.2 reader accepts both schema 1 and schema 3 files.
- A writer writes schema 1 when it emits only 0.1 record types, so 0.1
  readers keep reading it, and schema 3 when it emits any 0.2 type.
- While the contract is 0.Y.Z, a new record type, subsystem or field is a
  minor version with new vectors; existing vectors keep their outcomes or the
  change is recorded as breaking in CHANGELOG.md.
- Adding vectors the reference already decides is a patch version.
  Changing a refusal code or the check order is a breaking change.
- No feature negotiation beyond the schema value: each schema is checked exactly. A writer that needs a
  record this spec lacks proposes it here first; it does not invent a type
  number.

## 11. Limits (stated, not hidden)

- No runtime writes TRN1 yet. RX_CRUMB and ARGUS_EVENT layouts were checked
  against the live omega and aienos sources named above, and a host-only
  scratch check fed the corpus bytes to those sources' hash functions
  (recorded in the lane LB report, not part of CI).
- Batch composition, KV page ownership and sampler state for an inference
  runtime have no record type yet; they wait for an inference runtime that
  exists (sovereign-core is scaffolding, omega has none).
- Cross-record checks beyond ARGUS continuity are left to replayers: a
  crumb's parent digest is not checked against an earlier RX_CRUMB record in
  the same file, and effect commits are not matched to intents. In 0.2.0
  the causal checks are join rules (section 5.5), not verifier rules.
- TRAIN_DISPATCH (type 20) has a number and no layout.
- No signature over the final digest. Anchoring the final digest in a signed
  receipt belongs to the receipt format, not to TRN1.
