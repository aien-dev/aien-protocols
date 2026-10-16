# Pi-Spark Task Message: PST1

**Status**: Draft v0.1 (ALLEN Pi/Spark lane C1, 2026-10-16; C3 added the magic, the check order and two codes). Not yet produced or read by any runtime. Reference checker and vectors: `tools/pst_verify.c`, `vectors/`.
**Contract version**: 0.1.0 (major zero: may change by minor bump, see VERSIONING.md)
**Wire version**: 1 (the `version` byte below)
**License**: Community Specification License 1.0
**Tracking**: aien-dev/aien-protocols-mv#28 (C1), parent #27, lane C of aien-dev/aien-architecture-mv#231
**Not in this document**: the Spark gate (C2), the Rust reader (C4), the order rules between messages (C5), the INTERPLANE mapping (C6), network framing and retry (aienos-mv#398).

## 1. Purpose

The Pi and the Spark need one agreed way to say "please do this task", "here is how it is going" and "here is the receipt". PST1 is that agreement: one bounded message that rides inside exactly one message of the existing reliable channel (M6-A), which rides inside the existing secure session (M6-B).

PST1 is a control-plane application format. It is not a network stack, not a scheduler, not an authorization layer and not a replacement for INTERPLANE. No PST1 message grants a capability or a permission (section 9).

## 2. Inventory of what already exists

| Existing piece | Where | Reused? | Reason |
|---|---|---|---|
| M6-A reliable channel | AIENOS `native/net/aienos_ctl.h` | Yes, as the carrier | In-order, exactly-once delivery inside one session. `CT_MAX_PAYLOAD` is 1024. Big-endian. |
| M6-B secure session | AIENOS `native/net/aienos_sec.h` | Yes, as the trust anchor | Mutual authentication against a pinned roster of one peer key, and an 8-byte `session_id`. TEST keys only today. |
| Cause id and origin run id | aien-architecture `docs/hardening/causal-id-join-v0.md` sections 2.1 and 2.3 (DRAFT, ADR 0025 PROPOSED) | Yes, as header fields | One 32-byte cause id is copied across every handoff, never minted again by the receiver. No runtime mints it yet. |
| Objective id | aien-sovereign-core `crates/aien-runtime/src/objective.rs` | Yes, as a header field | SHA-256 of `AIEN_E2E_OBJECTIVE_V1`, a newline, and the objective text. Written on the Spark by the operator tool, never by the daemon. |
| Effect ledger | aien-sovereign-core `crates/aien-runtime/src/effects.rs` | Yes, as the reconciliation authority | States OPEN, DONE, NOT_DONE, UNRESOLVED. Uncertain results are reconciled against it. |
| ALLEN subject | AIENOS `docs/adr/0018-allen-subject-state-object.md` | Yes, as a reference | The 32-byte agent id. No key material travels. |
| `aien-event-protocol`, `aien-action-protocol` | this repository, `crates/` | No | JSON with unbounded text and free-form `serde_json::Value` payloads. They cannot meet a fixed size limit. |
| TRN1 | this repository, `specs/execution-transcript/` | Pattern only | The house pattern for a byte format with a C reference checker and refusal codes. TRN1 is little-endian; PST1 is not (section 6). |
| INTERPLANE core | `interplane` `rust/crates/interplane-core` | No (mapped only for real tool calls, C6) | It translates tool requests. It is not a scheduler, a link or an authority. |

## 3. Layering

| Layer | Proves or does | Trust |
|---|---|---|
| M6-B | Who the peer is (the pinned key) and which session this is (`session_id`). | Trusted because the transport proved it. |
| M6-A | Delivers each message in order, exactly once, inside one session. | Trusted because the transport proved it. |
| PST1 | Says what the message means: which task, which objective, which kind of event. | Every PST1 field is a claim by the sender. |

Rules that follow:

1. The peer and the session are never read from a PST1 field. A receiver takes them from the transport and ignores any PST1 field that claims otherwise. PST1 has no peer field and no session field.
2. A PST1 field that the receiver can check against its own authoritative records (objective id, ALLEN subject id, effect state) is checked before it is believed.
3. A transport acknowledgement means "the message arrived". It never means "the work is done" (section 8).

## 4. Fixed header

One PST1 message is a 224-byte fixed header followed by `payload_len` bytes of payload. All integers are big-endian. Every reserved byte is zero on send and refused if non-zero on receipt.

| Offset | Size | Field | Allowed values |
|---|---|---|---|
| 0 | 4 | `magic` | The ASCII bytes `PST1` (0x50 0x53 0x54 0x31) |
| 4 | 1 | `version` | 1 |
| 5 | 1 | `type` | 1 to 14 (section 5) |
| 6 | 2 | `reserved0` | 0 |
| 8 | 32 | `cause_id` | Not all zero |
| 40 | 32 | `origin_run_id` | Any value (opaque, copied) |
| 72 | 32 | `objective_id` | Not all zero for `request`; copied on every later message |
| 104 | 32 | `subject_id` | The ALLEN subject reference (ADR 0018); no key material |
| 136 | 16 | `parent_task_id` | All zero means "no parent" |
| 152 | 16 | `task_id` | Not all zero |
| 168 | 16 | `idempotence_key` | Not all zero; see section 8 |
| 184 | 4 | `ordinal` | u32; see section 5 |
| 188 | 1 | `effect_class` | 0 NONE, 1 COMPUTE, 2 EFFECT |
| 189 | 1 | `reserved1` | 0 |
| 190 | 2 | `payload_len` | 0 to 800 |
| 192 | 32 | `payload_digest` | SHA-256 of the payload bytes (of the empty string when `payload_len` is 0) |

Total header: 224 bytes.

Change from Draft v0 (C3, aien-protocols-mv#30): Draft v0 had no magic, so a receiver could not tell a PST1 message from any other 1024-byte blob, and the C3 vectors could not test a "bad magic" refusal. The 4-byte magic now opens the header. To keep the header at 224 bytes (and the 800-byte payload cap), `reserved1` shrank from 3 bytes to 1 and `reserved2` was removed. Every field after `type` moved by 4 bytes, except `payload_digest`, which stays at 192.

`effect_class` is a claim about the work, not a permission. EFFECT work still needs a real grant from the Spark approval desk (lane G, G6).

### 4.1 Check order

A receiver checks one message in this order and reports the first rule that fails. The C reference checker (`tools/pst_verify.c`) and every other reader follow the same order, so the same bytes always give the same code.

1. Fewer than 224 bytes, or more than 1024 bytes: `PST_BAD_LENGTH`.
2. `magic` is not `PST1`: `PST_BAD_MAGIC`.
3. `version` is 0 (below the lowest version this receiver accepts): `PST_DOWNGRADE`. `version` above 1: `PST_BAD_VERSION`.
4. `type` is 0 or above 14: `PST_BAD_TYPE`.
5. `reserved0` or `reserved1` is non-zero: `PST_RESERVED_NONZERO`.
6. The bytes after the header are fewer than `payload_len`: `PST_BAD_LENGTH`. (A `payload_len` above 800 always lands here or in step 1, since 224 plus 801 is more than 1024.)
7. The bytes after the header are more than `payload_len`: `PST_TRAILING_BYTES`.
8. `effect_class` above 2: `PST_BAD_EFFECT_CLASS`.
9. `cause_id` all zero: `PST_NO_CAUSE`.
10. `task_id` all zero, then `idempotence_key` all zero: `PST_NO_TASK`.
11. `type` is `request` and `objective_id` is all zero: `PST_NO_OBJECTIVE`.
12. `payload_digest` differs from the SHA-256 of the payload: `PST_DIGEST_MISMATCH`.

The checks that need more than one message (`PST_WRONG_SIDE`, `PST_SUBJECT_MISMATCH`, a version lower than the one already used in the session) come after these and belong to the session rules (C5).

## 5. Message types

`request`, `cancel request` and `resume request` are sent by the Pi. Every other type is sent by the Spark. A message of a type from the wrong side is refused.

| Value | Type | Side | Payload |
|---|---|---|---|
| 1 | `request` | Pi | Task description bytes (UTF-8 text, or the request body named by the task kind) |
| 2 | `accepted` | Spark | Empty |
| 3 | `queued` | Spark | Empty |
| 4 | `running` | Spark | Empty |
| 5 | `text_chunk` | Spark | One piece of streamed text |
| 6 | `waiting_for_approval` | Spark | The 32-byte digest of the action awaiting approval |
| 7 | `completed` | Spark | The 32-byte digest of the result |
| 8 | `failed` | Spark | A short reason code and text |
| 9 | `cancelled` | Spark | Empty |
| 10 | `uncertain_after_disconnect` | Spark | Empty. Means "not known whether it happened" (section 8) |
| 11 | `resume_snapshot` | Spark | The state of one task as read from the authoritative records |
| 12 | `receipt_reference` | Spark | The 32-byte digest of a receipt held on the Spark |
| 13 | `cancel_request` | Pi | Empty |
| 14 | `resume_request` | Pi | Empty |

`ordinal` numbers the messages of one task from the sender's side, starting at 0 and rising by one. `text_chunk` messages of one task carry consecutive ordinals so a lost or repeated chunk is visible. The order rules between types are not defined here; they belong to C5.

Status is derived from authoritative execution state on the Spark. A `completed`, `failed` or `cancelled` message is only sent after the authoritative record says so. Events are hints until the receiver has checked what it can.

## 6. Size and byte order

1. One PST1 message (224 header bytes plus up to 800 payload bytes, so at most 1024) fits in one M6-A message (`CT_MAX_PAYLOAD`, 1024). A message that would be longer is refused with `PST_BAD_LENGTH`.
2. A long text stream is split into numbered `text_chunk` messages. There is no reassembly of one PST1 message across several transport messages. The receiver joins chunks by ordinal, not by transport framing.
3. **Byte order is big-endian**, to match the M6-A and M6-B headers PST1 rides inside, so one implementation reads one convention on the whole link. TRN1 chose little-endian for a file format that never rides on this link. This choice is a recommendation made without a measurement; it is not final until C3 vectors and the aienos lane both accept it.

## 7. Refusal codes

A receiver refuses the message and takes no action. It reports one of these, choosing by the check order in section 4.1. A refusal never changes task state.

| Code | Meaning |
|---|---|
| `PST_BAD_MAGIC` | The first 4 bytes are not `PST1` |
| `PST_BAD_VERSION` | `version` is above 1 (unknown version) |
| `PST_DOWNGRADE` | `version` is 0 (below the lowest accepted version), or lower than the version already used in this session |
| `PST_BAD_TYPE` | `type` is 0 or above 14 |
| `PST_WRONG_SIDE` | A Pi-only type from the Spark, or the reverse |
| `PST_BAD_LENGTH` | Fewer than 224 bytes, more than 1024 bytes, `payload_len` above 800, or fewer payload bytes than `payload_len` |
| `PST_TRAILING_BYTES` | More payload bytes than `payload_len` (and the total is at most 1024) |
| `PST_RESERVED_NONZERO` | Any reserved byte is non-zero |
| `PST_NO_CAUSE` | `cause_id` is all zero |
| `PST_NO_TASK` | `task_id` or `idempotence_key` is all zero |
| `PST_NO_OBJECTIVE` | A `request` whose `objective_id` is all zero (added in C3: Draft v0 stated the rule but named no code) |
| `PST_DIGEST_MISMATCH` | `payload_digest` does not match the payload |
| `PST_BAD_EFFECT_CLASS` | `effect_class` above 2 |
| `PST_SUBJECT_MISMATCH` | `subject_id` differs from the subject bound to this session |

A receiver that gets work with no cause id refuses it (`PST_NO_CAUSE`); it does not mint one. The cause id is minted once, where the outside request first enters AIEN (on the Pi, at the user's turn), per the causal id join spec.

## 8. Exactly once has limits

1. A transport acknowledgement is not "done". M6-A delivers a message once; it says nothing about whether the work ran.
2. A repeated `request` with the same `idempotence_key` and the same `task_id` is recognised as the same request and does not start a second task.
3. When the link drops while an effect is in flight, the Spark reports `uncertain_after_disconnect`. It does not report `failed` or `cancelled` when it does not know.
4. An effect whose outcome is unknown is reconciled against the Spark effect ledger (OPEN, DONE, NOT_DONE, UNRESOLVED) before anything is retried. A possibly committed effect is never sent again on the strength of a retry alone.
5. A local model's routing choice on the Pi grants nothing. Model output is never an authorization.

## 9. No capability, no permission

No message type, field or value in PST1 grants a capability, a permission, an approval or an identity. `waiting_for_approval` asks; it does not decide. Approvals come from the Spark approval desk and are not carried as PST1 fields. The ALLEN subject stays the authority on the Pi.

## 10. Open questions

These are stated plainly so the C3 vectors and the neighbouring lanes can settle them. None is decided here.

1. Task id width (16 bytes here) and whether it should instead be derived from the cause id. UNVERIFIED.
2. Whether `resume_snapshot` needs its own payload layout, or a task-kind byte inside the payload. To be fixed by G3 and C5.
3. The aienos lane (aienos-mv#398) must confirm it can carry 1024-byte messages end to end and agree the framing.
4. Whether big-endian stays (section 6, item 3).
