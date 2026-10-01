# Crumb Reader Contract: CRB1 visible record

**Status**: Stable (extracted from the running implementation; no new format features)
**Contract version**: 1.0.0
**Wire schema version**: 1 (the `schema_version` field below)
**License**: Community Specification License 1.0
**Reference implementation**: `aien-sovereign-core`, `crates/crumbs/src/visible.rs` (`VisibleCrumb::from_bytes`), Rust
**Other implementations**: `omega`, `src/crumbline/cl_crumb.c` (`cl_crumb_decode`), C. Future: an Omega-compiled reader.
**Conformance corpus**: [`vectors/`](vectors/) with [`vectors/expected.txt`](vectors/expected.txt)

## 1. Purpose

A crumb lesson file is the only thing a learner sees of a crumb: an ordered list
of opaque `INPUT -> OUTPUT` examples plus the minimum structure needed to parse
them. This contract states, in language-neutral terms, which byte strings are
valid CRB1 records, what a reader must extract from them, and which numbered
refusal a reader must return for every invalid byte string. Any reader that
passes the shared corpus with zero differences may stand in for any other.

The contract is the byte format and the outcome, never a language type. No
Rust enum, struct layout or serialization crosses it.

## 2. Reader interface

A reader is a pure function of one read-only byte buffer, given as a pointer
and a length (or the language's equivalent). The caller owns the buffer; the
reader borrows it for the duration of one call and keeps no reference. The
reader returns exactly one of:

- **accept**, with the decoded record (section 4), or
- **refuse**, with one refusal code (section 5).

A reader performs no I/O, allocation visible to the caller, clock reads or
randomness that can change the outcome. On refusal it exposes no partial
record and no content of the input (codes are bare numbers).

## 3. Byte format (schema 1)

All integers are unsigned little-endian. Offsets are from the start of the
buffer.

| Offset | Size | Field | Valid values |
|---|---|---|---|
| 0 | 4 | magic | ASCII `CRB1` (`43 52 42 31`) |
| 4 | 2 | schema_version | `1` |
| 6 | 1 | encoding | `1` = decimal UTF-8 lanes, `2` = raw little-endian lanes |
| 7 | 1 | flags | bit 0 = budget present; bits 1..7 must be 0 |
| 8 | 1 | in_arity | lanes per input, 1..8 |
| 9 | 1 | out_arity | lanes per output, 1..8 |
| 10 | 1 | in_lane_bytes | encoding 1: `0`; encoding 2: `1`, `2`, `4` or `8` |
| 11 | 1 | out_lane_bytes | same rule as in_lane_bytes |
| 12 | 4 | n | number of examples, 1..64 |
| 16 | ... | examples | n times: `u32 in_len, in_len bytes, u32 out_len, out_len bytes`; each length at most 168 |
| ... | 16 | budget (only if flags bit 0) | `max_candidates u32, max_depth u32, max_oracle_queries u32, max_program_ops u32` |

The buffer ends exactly after the last example, or after the budget when
present. No trailing bytes.

**Lane fields.** An example field holds `arity` lane values.

- Encoding 2 (raw): the field length is exactly `lane_bytes * arity`; lane `k`
  is bytes `[k*lane_bytes, (k+1)*lane_bytes)` read as an unsigned
  little-endian integer.
- Encoding 1 (decimal): the field is UTF-8 text made of exactly `arity`
  parts separated by single ASCII spaces (`0x20`). Each part is a canonical
  base-10 unsigned integer: one or more ASCII digits `0`..`9`, no sign, no
  leading zero unless the part is exactly `0`, value at most
  18446744073709551615 (2^64 - 1).

Every valid record has exactly one byte encoding, so re-encoding an accepted
record reproduces the input buffer byte for byte.

## 4. Decoded record

On accept the reader yields: `encoding`, `in_arity`, `in_lane_bytes`,
`out_arity`, `out_lane_bytes`, `n`, for each example the `in_arity` input lane
values and `out_arity` output lane values as unsigned 64-bit integers, and the
four budget values when flags bit 0 is set.

## 5. Refusal codes

Zero means accept. A refusal is a negative integer from this table, and only
from this table.

| Code | Name | Meaning |
|---|---|---|
| -1 | MAGIC | first four bytes are not `CRB1` |
| -2 | VERSION | schema_version is not 1 |
| -3 | SHAPE | encoding, arity or lane-bytes value outside its valid set |
| -4 | LANE | a lane field has the wrong length, the wrong number of decimal parts, invalid UTF-8, or a decimal value above 2^64 - 1 |
| -5 | LENGTH | the buffer ends before a field it must contain, n is 0 or above 64, an example length is above 168, or bytes remain after the record |
| -6 | NONCANONICAL | flags has a reserved bit set, or a decimal part is not canonical (empty, a non-digit character, or a leading zero) |

## 6. Check order (determines the code)

A reader refuses with the code of the **first** failing check in this order.
Reading past the end of the buffer at any step is LENGTH (-5), including
inside the magic.

1. Read 4 bytes (magic). Not `CRB1`: MAGIC.
2. Read u16 schema_version. Not 1: VERSION.
3. Read u8 encoding. Not 1 or 2: SHAPE.
4. Read u8 flags. Any bit other than bit 0 set: NONCANONICAL.
5. Read all four of in_arity, out_arity, in_lane_bytes, out_lane_bytes, then
   check: arity outside 1..8: SHAPE; lane bytes invalid for the encoding: SHAPE.
6. Read u32 n. n = 0 or n > 64: LENGTH.
7. For each example in order: read u32 in_len (above 168: LENGTH), read in_len
   bytes; read u32 out_len (above 168: LENGTH), read out_len bytes. Only after
   both fields of this example are read, validate the input lanes, then the
   output lanes:
   - raw: length differs from `lane_bytes * arity`: LANE.
   - decimal: not valid UTF-8: LANE; number of space-separated parts differs
     from arity: LANE; then for each part in order: empty, contains a byte
     other than `0`..`9`, or has a leading zero: NONCANONICAL; value above
     2^64 - 1: LANE.
8. If flags bit 0: read four u32 budget values.
9. Bytes remain: LENGTH.

Note for implementers: step 7 distinguishes invalid UTF-8 (LANE) from valid
UTF-8 that is not a digit (NONCANONICAL), because the reference checks UTF-8
validity before canonical form. An implementation without a UTF-8 validator
must reproduce this split to conform (vectors r031 and r032).

## 7. Determinism rule

For the same input bytes every conforming reader, on every run, returns the
same outcome: the same accept or refuse, the same refusal code, and the same
decoded values. The outcome is compared through one canonical text line,
which is also the corpus manifest format:

```text
ok enc=E in=AxB out=CxD n=N[ budget=C1,C2,C3,C4] | i1 i2 -> o1 | ...
refuse CODE
```

`A`/`C` are in/out arity, `B`/`D` in/out lane bytes, lane values in base 10,
one ` | ins -> outs` group per example in order. The budget group appears only
when flags bit 0 is set.

## 8. Conformance corpus

`vectors/expected.txt` lists every vector as `<file> <outcome line>`. Lines
starting with `#` are comments. The manifest is plain text so C, shell and
Omega harnesses can read it without a JSON parser.

| Group | Files | Source |
|---|---|---|
| Family vectors | `v001.crb` .. `v122.crb` | `crumbs vectors DIR` (one per registered crumb family, seed 7), byte-identical to omega `tests/crumbline/vectors` at contract 1.0.0 |
| Edge positives | `p001.crb` .. `p005.crb` | built byte by byte by `tools/make-vectors.sh`: budget present, decimal 0 and 2^64 - 1, raw 1/2/8-byte lanes, 64 examples |
| Refusals | `r001.crb` .. `r044.crb` | built byte by byte by `tools/make-vectors.sh`; each names its expected code; includes check-order cases r037..r040 |

Regenerate with `tools/make-vectors.sh <path to crumbs binary> vectors`. The
script is shell only. Every expected outcome is checked by the reference
reader (`crates/crumbs/tests/visible_conformance.rs`), so a hand-written
expectation that the reference disagrees with fails CI.

A conforming harness prints one summary line:

```text
CRUMB_VISIBLE_V1_CONFORMANCE impl=<rust|c|osc> pass=N fail=0
```

## 9. Versioning

- Wire schema 1 is the only accepted schema. A reader refuses every other
  schema value with VERSION; it never reinterprets an older or newer record.
- A change to the byte layout or the meaning of a field is a new wire schema
  and a new major contract version, with its own corpus; schema 1 vectors
  stay and keep their outcomes.
- Adding vectors that the reference already decides is a patch version.
  Changing a refusal code or the check order is a major version.
- No feature negotiation: there is one schema, checked exactly.

## 10. Ownership switch (from the migration plan)

An implementation may replace the current one inside a consumer only after it
passes 100% of this corpus with zero differences in outcome lines, and after
the agreed differential fuzz shows zero disagreements against the reference.
The replaced implementation stays one release as a differential reference.
