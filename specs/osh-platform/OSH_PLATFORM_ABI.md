# OSH Platform ABI v1 (Omega-native shell, working name `osh`)

**Status**: v1 DRAFT, not frozen: freezes after OSC-EXT-BYTES lands and the Linux adapter has consumed it once.
**ABI version field**: `1` (nothing is frozen, so any v1 field may still change until the freeze; after it, changes bump the version)
**License**: Community Specification License 1.0
**Origin**: `aien-dev/aien-architecture#158`. This file makes the shell-core to platform boundary normative. It claims no implementation: no shell, no adapter and no OSC-EXT-BYTES exist on `main` at the time of writing (omega `b980783`; design only, `docs/osc/OSC-EXT-BYTES-DESIGN.md`).
**Conformance vectors**: [`vectors/`](vectors/), [`vectors/expected.txt`](vectors/expected.txt), generated inputs by [`tools/make-vectors.sh`](tools/make-vectors.sh)
**Not covered**: shell language semantics beyond what the request record needs (owned by the first-release freeze in `aien-architecture`), the Omega compiler, kernel IPC.

## 1. Model

The shell core is Omega code compiled from `.osc`. It tokenizes, parses, expands and builds request records. It never launches anything. A platform adapter (Linux host, AIENOS native) owns every effect: it supplies input bytes, variable values, and executes request records. One core, many adapters, shared vectors. The adapter must not re-implement tokenization, parsing or expansion, and must never hand shell text to `bash -c`, `sh -c`, `system()` or an equivalent.

Core entry points are bounded and resumable. Each call takes two borrowed slices (`inp` input bytes, `w` workspace cells) and returns one `u64` status. The core stores no pointers and no handles. Every cross-reference is an integer offset into `inp` or an index into a workspace table, re-checked against slice length on every access.

## 2. Encoding rules

- All multi-byte integers are little-endian, fixed width, no padding, no alignment assumption, no floating point, no host struct layout. (Other specs in this repository use big-endian; this one does not. Do not mix.)
- A **cell** is a `u64`. The workspace and request record are sequences of cells. Wire form (section 7.3) serializes each cell as 8 bytes little-endian.
- A **byte slice** is `(address, length)` borrowed for one call. A length of 0 is valid and must not be dereferenced.
- Bytes are bytes. Paths, arguments and variable values are raw bytes; a NUL byte is never valid in any of them and is refused (`NUL_BYTE`, `VALUE_NUL`). The core never assumes UTF-8.
- Magic constants are numeric values stated in hex below, not text.

## 3. Versioning and refusal of unknown versions

Every exchanged blob (workspace, request record, platform call frame) begins with a header of cells. The request record keeps its eight-cell header (section 7.1), so its version cell is cell 5 instead of cell 1:

| cell | field | v1 value |
|---|---|---|
| 0 | `magic` | workspace `0x4F534857` ("OSHW"); request record `0x4F524551` ("OREQ"); platform frame `0x4F534846` ("OSHF") |
| 1 (request record: 5) | `abi_version` | `1` |

Check order, first failure wins, each refusal numbered in section 5.3: slice too short for the header (`ABI_LENGTH`), wrong magic (`ABI_MAGIC`), `abi_version` not exactly 1 (`ABI_VERSION`), workspace shorter than 11456 cells (`WORKSPACE_SIZE`), any reserved field nonzero (`ABI_RESERVED`). A reader never guesses at a newer version, never reads past a refusal, and never partially applies a blob. A version bump changes `abi_version`; v1 readers refuse v2 blobs.

## 4. Ownership and lifetimes

1. **Borrow per call.** Slices passed to a call are valid only for that call. The callee must not retain them. The adapter owns the workspace and input buffer for the session; the core owns nothing.
2. **Append-only input.** `inp` is append-only within one list. The adapter guarantees it ends in a newline (`0x0A`) before any entry call except the explicit end-of-input flush used by tests. Offsets into `inp` stay valid across resumes.
3. **No identity in handles.** Stream ids, task ids, request pointers and workspace addresses are transient. They are never written to durable state, receipts or logs as identity. Identity is a digest, a name in an authority index, or a principal id (section 9).
4. **Epoch.** The adapter keeps a `u64` `session_epoch`, incremented on every session reset or restart. Every transient id carries the epoch of the session that created it. A call using an id from another epoch fails `STALE`.
5. **Durable state** (may be persisted, re-read after restart): exported and unexported variable names and values, current location (section 8.2), last pipeline status, positional parameters. **Transient state** (never persisted, rebuilt from input or discarded): tokens, parse tables, request record, staging area, cursors, stream ids, task ids, partially expanded bytes. The adapter may drop transient state at any time; an idempotent resume re-derives it.
6. **Workspace ownership.** Only the core writes the workspace, except the staging area, which only the adapter writes (section 6.3).

## 5. Step and status protocol

### 5.1 Entries and phases

Three entries, called in order by the adapter: `lex_run(inp, w)`, `parse_run(inp, w)`, `expand_run(inp, w)`. Each call does at most a fixed step budget (lexer 1024 input bytes, parser 64 tokens, expander 1024 output bytes), writes any record first, advances its cursor in the session last, and returns one status.

### 5.2 Status values (returned in the result register)

| value | name | meaning and adapter action |
|---|---|---|
| 0 | `PHASE_DONE` | this phase finished for the buffered input; call the next entry |
| 100 | `NEED_MORE_INPUT` | input ends inside an open quote, after a trailing backslash, or after a trailing `\|`, `&&`, `\|\|`; append the next line and call the same entry again |
| 101 | `BUDGET_EXHAUSTED` | budget spent, progress committed; call the same entry again with no new input |
| 102 | `NEED_VAR` | expander needs a variable; answer per section 6.3, then call `expand_run` again |
| 103 | `PIPELINE_READY` | a valid request record is in the workspace (section 7); execute it, then update variables and `$?` |
| 104 | `COMPLETE` | the current list has no more pipelines (the "list done" state); input for it is consumed |
| 200 to 255 | `ERROR` | refusal; code in the status value, offset in the session (section 5.4); session is terminal until reset |

A call that returns 100, 101 or 102 is idempotent: repeating it without change yields the same result. Statuses 1 to 99 and 105 to 199 are reserved; an adapter seeing one treats it as `ABI_VERSION`-class failure and resets the session.

### 5.3 Refusal codes (v1 draft numbering; named, stable once frozen)

- Capacity, raised before any effect that depends on the text: 201 `CAP_LINE` (line over 4096 bytes), 202 `CAP_TOKENS` (128), 203 `CAP_CMDS` (32 per line), 204 `CAP_PIPELINES` (16 per line), 205 `CAP_PIPE_LEN` (8 commands per pipeline), 206 `CAP_WORDS` (32 raw words per command), 207 `CAP_ASSIGNS` (16 per command), 208 `CAP_REDIRS` (8 per command), 209 `CAP_FIELDS` (32 after splitting), 210 `CAP_OUT` (8192 expanded bytes per pipeline), 211 `CAP_VALUE` (1024 bytes per variable value), 212 `CAP_VARREQ` (64 variable requests per pipeline).
- ABI: 213 `WORKSPACE_SIZE`, 214 `ABI_MAGIC`, 215 `ABI_VERSION`, 216 `ABI_LENGTH`, 217 `ABI_RESERVED`, 218 `REQ_FIELD` (a direct request, section 11, has an invalid field).
- Unsupported or malformed syntax, one code each: 220 `NUL_BYTE`, 221 `BACKTICK`, 222 `GLOB`, 223 `TILDE`, 224 `PARAM_OP`, 225 `SPECIAL_PARAM`, 226 `CMDSUB`, 227 `BACKGROUND`, 228 `SUBSHELL`, 229 `HEREDOC`, 230 `CASEEND`, 231 `REDIR_OTHER`, 232 `FD_RANGE`, 233 `IF_COMPOUND`, 234 `LOOP`, 235 `CASE`, 236 `GROUP`, 237 `FUNCTION`, 238 `NEGATION`, 239 `UNSUPPORTED_BUILTIN`, 240 `IFS_ASSIGN`, 241 `SYNTAX_EMPTY_CMD`, 242 `SYNTAX_REDIR_TARGET`, 243 `AMBIGUOUS_REDIRECT`.
- Value-dependent, raised by the expander: 244 `VALUE_NUL`, 245 `VALUE_GLOB` (an unquoted expansion result contains `*`, `?` or `[`; refused so behavior never silently differs from a globbing shell).

Codes 246 to 255 are reserved. Meaning of each syntax code is its name in the first-release language freeze; this ABI only fixes the number.

### 5.4 Error offset

On `ERROR` the session holds the code and a byte offset into `inp`. For lexer and parser refusals the offset is the index of the first byte at which refusal is decidable (for `echo $(x)` the `(`, offset 6; for `a & b` the `&`, offset 2). For expander refusals it is the start offset of the word being expanded. Vectors fix the offset; two cores that disagree on an offset are non-conforming.

After `ERROR` the adapter reports the shell exit status 2 for that list, resets the session (new `session_epoch`), keeps durable state, and discards unexecuted pipelines of that list. Pipelines of earlier lists have already run. Validation is incremental per complete list: there is no whole-script atomicity. Size refusals that depend on variable values (`CAP_FIELDS`, `CAP_OUT`) fire before that pipeline only, so in `a; b$HUGE` pipeline `a` has already run.

## 6. Workspace

### 6.1 Layout (cells, v1 draft; total 11456 cells = 91,648 bytes)

| region | cells | content |
|---|---|---|
| `SESSION` | 0 to 63 | header and cursors (6.2) |
| `TOKENS` | 64 to 575 | 128 tokens x 4 cells |
| `CMDS` | 576 to 831 | 32 command entries x 8 cells |
| `PIPES` | 832 to 895 | 16 pipeline entries x 4 cells |
| `STAGING` | 896 to 1927 | adapter-written variable answer (6.3) |
| `REQUEST` | 1928 to 3263 | request record (section 7): 1320 cells used (1928 to 3247), 3248 to 3263 zero |
| `OUT` | 3264 to 11455 | expanded bytes, one byte per cell (value 0 to 255) |

The adapter must pass exactly 11456 cells; fewer is `WORKSPACE_SIZE`. Packing OUT eight bytes per cell is a possible later change and would be a version bump. The token, command and pipeline table layouts are internal to the core; adapters never read them. Region offsets are generated from one layout list so core and adapter cannot drift (open item, section 14).

### 6.2 Session cells (draft assignment; exact internal cells beyond these are set by the layout list)

0 `magic`, 1 `abi_version`, 2 `phase`, 3 `last_status`, 4 `error_code`, 5 `error_offset`, 6 `input_cursor`, 7 `workspace_cells` (expected 11456), 8 `var_req_kind`, 9 `var_req_a`, 10 `var_req_len`, 11 `var_req_seq`, 12 to 47 core-internal, 48 to 63 reserved (explicit nesting stack for later `$( )` support; zero in v1; a nonzero value is `ABI_RESERVED`).

### 6.3 Variable protocol

On status 102 the core writes `var_req_kind`: 1 NAME (`var_req_a` = byte offset of the name in `inp`, `var_req_len` = length), 2 `$?`, 3 positional `k` (`var_req_a` = k, 0 to 9), 4 `$#`, 5 positional list. The adapter writes `STAGING` as: cell 0 `found` (0 or 1), cell 1 `len` (0 to 1024), cell 2 `npos`, cell 3 zero, cells 4 onward the value bytes, one per cell. A value over 1024 bytes is `CAP_VALUE`. Kind 5 is answered with `npos` only (`found` = 1, `len` = 0); the core then requests each positional with kind 3, each counting toward `CAP_VARREQ`. An unset name is `found` = 0, not an error. The core consumes `STAGING` on the next `expand_run`; a repeated call before consumption is safe.

## 7. Request record

### 7.1 Layout

Valid in `REQUEST` when `PIPELINE_READY` is returned. Header, 8 cells: `{magic 0x4F524551, ncmds, connector_after, flags, out_used, abi_version = 1, 0, 0}`. `connector_after`: 0 none, 1 `;` or newline, 2 `&&`, 3 `\|\|`. `flags` bit 0 `DIRECT` (section 11); all other bits zero. Then `ncmds` blocks (up to 8) of exactly 164 cells:

| cells | content |
|---|---|
| 4 | `{nargv, nassign, nredir, builtin_id}` |
| 64 | 32 argv entries `{off, len}` |
| 64 | 16 assignment entries `{name_off, name_len, val_off, val_len}` |
| 32 | 8 redirection entries `{kind, fd, target_off, target_len}` |

`builtin_id`: 0 external or not a builtin, 1 `cd`, 2 `pwd`, 3 `printf`, 4 `export`, 5 `unset`, 6 `exit`. Redirection `kind`: 1 input, 2 output, 3 append, 4 duplicate. For kinds 1 to 3, `fd` is the descriptor being redirected (0 to 2) and `target_*` names the target bytes. For kind 4 (`N>&M`, `N<&M`), `fd` is N and `target_off` holds the source descriptor M (0 to 2) with `target_len` 0. Entries beyond `nargv`, `nassign`, `nredir` are zero. `off` and `len` index the `OUT` region (byte `off` is cell `3264 + off`); `out_used` is the high-water mark. An argv entry of length 0 is a real empty argument, present in `nargv`.

### 7.2 Execution order

Within one pipeline: commands start concurrently with pipes connected left to right; each command's redirections apply in record order, left to right, after pipe setup, so `>o 2>&1` and `2>&1 >o` differ as in POSIX shells. Pipeline status is the last command's status. `connector_after` decides whether the next pipeline runs. Prefix assignments with a nonempty argv apply only to that command's environment; with an empty argv they change shell state. Builtins run in the parent session when the pipeline has one command, and in a child context otherwise, so `cd x \| cat` does not change the parent location.

### 7.3 Wire form

For transfer between processes or machines: 16-byte header `{magic u32 0x4F534851 ("OSHQ"), abi_version u16, kind u16 (1 = request record), total_len u32, reserved u32 = 0}` followed by the cells as 8-byte little-endian integers: header block, command blocks, then `out_used` bytes of OUT. `total_len` is the exact byte length including the header; any other length is `ABI_LENGTH`.

## 8. Platform operations

The adapter implements these. Each takes borrowed slices and returns a frame `{error u32, value u64}`. Error codes are in 8.6. Every id argument is checked for epoch (section 4.4).

### 8.1 Streams and buffers

`STREAM_OPEN(location, mode: read | write | append | create_excl)`, `STREAM_READ(stream, out_slice) -> n` (0 means EOF), `STREAM_WRITE(stream, in_slice) -> n` (partial writes allowed; the caller loops), `STREAM_CLOSE(stream)`, `STREAM_DUP(src_stream, dst_fd)`, `PIPE_CREATE() -> (read_stream, write_stream)`. Pipes are bounded and apply backpressure: a writer to a full pipe gets `WOULD_BLOCK` or blocks, never unbounded buffering. A write to a pipe whose reader closed returns `BROKEN_PIPE`. Standard descriptors 0 to 2 are the only fixed numbers.

### 8.2 Storage locations

A location is `{scheme u8, len u32, bytes}`. Scheme 1 `POSIX_PATH`: raw bytes, no NUL, relative to the session location or absolute. Scheme 2 `STORE_DIGEST`: a 32-byte content digest naming a native Artifact Store object. Native Store locations are never parsed from, converted to or presented as POSIX paths, and a Store object is not a file in a directory tree. Digests are authority; any name is convenience. `LOC_GETCWD() -> location`, `LOC_CHDIR(location)`. Scheme availability is per adapter: an unavailable scheme returns `UNAVAILABLE`. How a human or AIEN names a Store location in shell syntax is not defined in v1 and is an R1.1 decision; v1 parsing yields only scheme 1.

### 8.3 Executable and service resolution

`RESOLVE(name_bytes, search_context) -> {class u8, target_ref}` where class is 1 `OMEGA_NATIVE_OP` (a compiled Omega operation hosted by the adapter), 2 `AIENOS_ARTIFACT` or 3 `AIENOS_SERVICE` (named by digest or service id, admitted through artifact validation), 4 `LINUX_EXECUTABLE` (a path found by the defined PATH rule, with the resolved bytes). The classes never fall back to each other. An unavailable class returns `UNAVAILABLE`. There is no implicit forwarding to another machine, and a Linux executable does not make an AIENOS artifact callable. `search_context` carries the PATH bytes taken from the session environment, never from process-global state the core did not see.

### 8.4 Execute, wait, cancel

`TASK_SPAWN(resolved, argv_slices, env_slices, stdio{0,1,2}, binding) -> task_id`, `TASK_WAIT(task, deadline) -> status`, `TASK_CANCEL(task, mode: interrupt | terminate)`, `TASK_STATE(task)`. `binding` is the authority record (section 9); spawn without a valid binding returns `DENIED`. On Linux, an interactive session runs each foreground pipeline in its own process group, hands it the terminal, and forwards an interrupt aimed at the shell to that group. A non-interactive session leaves the pipeline in the shell's process group, so a group-wide interrupt reaches the shell and the pipeline together; in that mode the shell does not die of the interrupt while waiting and ends with status 130 if the last command died of SIGINT. SIGINT and SIGQUIT ignored at entry stay ignored in children. R1 has no job control: a stopped pipeline member cancels the whole pipeline (status 128 plus the stop signal). Exit status follows POSIX shell convention (127 not found, 126 found but not executable, 128 plus signal); exact agreement with the pinned reference shell is checked by the differential suite, not asserted here.

### 8.5 Permissions and limits

`PERM_CHECK(binding, op)` returns `OK` or a denial reason. `LIMITS_GET() -> {max_streams, max_tasks, max_pipe_bytes, max_output_bytes}`. v1 minimums the adapter must support: 8 concurrent tasks per pipeline (matches `CAP_PIPE_LEN`), 3 standard streams plus 16 open streams, 64 KiB per pipe. Exceeding a limit returns `LIMIT`, never silent truncation.

### 8.6 Platform error codes (`error` field)

0 `OK`, 1 `DENIED`, 2 `REVOKED`, 3 `STALE`, 4 `NOT_FOUND`, 5 `UNAVAILABLE`, 6 `INVALID_ARG`, 7 `LIMIT`, 8 `INTERRUPTED`, 9 `BROKEN_PIPE`, 10 `IO`, 11 `OUTCOME_UNKNOWN`, 12 `CAP_DOMAIN_MISMATCH`, 13 `CAP_GEN_NARROW`, 14 `NOT_SUPPORTED`, 15 `WOULD_BLOCK`, 16 `PARTIAL_LAUNCH`. Platform errors are a separate namespace from refusal codes. Unknown codes are treated as `IO`, never as `OK`.

## 9. Authority rules

1. Shell variables, environment contents, command names, PATH and `argv[0]` never grant authority. A name is a lookup key only.
2. Every effect (open for write, spawn, chdir into a protected location, any native service call) carries a `binding`: `{principal_id[32], domain u8, cap_index u32, cap_generation u64, resource_class u16, operation u16}`. The effect boundary (adapter plus the capability authority it calls) validates principal, resource and operation together at the moment of the effect, not at parse time. A binding that was valid when the request was built can be `REVOKED` or `STALE` when used; the effect then does not happen and the error is returned.
3. Capability domains differ. `domain` 1 is the kernel IPC table (32-bit generation, 32-bit index). `domain` 2 is the hosted capability authority (64-bit generation). A generation is never narrowed, widened by guessing or reinterpreted across domains. v1 defines no bridge: a binding whose domain does not match the resource's domain fails `CAP_DOMAIN_MISMATCH`, and a domain-1 binding with `cap_generation` above `0xFFFFFFFF` fails `CAP_GEN_NARROW`. A future bridge is a versioned mapping (its own `mapping_version`, an explicit table, bidirectional refusal for unmapped entries) added by an ABI version bump.
4. A parsed command allowlist does not sandbox a child. A spawned process inherits whatever authority its adapter grants it. Containment is claimed only where the platform enforces it and the enforcement has evidence.
5. The shell and this ABI have no grant, mint or revoke operation. The capability root mints and revokes. A request builder may describe an effect and ask for it; it may not authorize it.
6. Recovery and read-only inspection must not depend on `osh`, and `osh` is not an unrestricted repair path: operator-authorized writes keep their own gate.

## 10. Interrupted effects and restart

An effect is one `TASK_SPAWN` or one write-class `STREAM_OPEN`. The adapter keeps a durable intent record before the effect and an outcome record after. Outcomes: `NOT_STARTED`, `COMPLETED(status)`, `FAILED_NO_EFFECT(error)`, `CANCELLED`, `OUTCOME_UNKNOWN`. After a crash, restart or lost connection, an intent with no outcome is reported `OUTCOME_UNKNOWN` with the request digest; the adapter never replays it. A new request is a new decision by the human or by AIEN. No operation is claimed reversible and none is claimed exactly-once. `EINTR`-style interrupted waits are retried by the adapter without re-running the effect. Partial launch failure (some commands of a pipeline started, a later one failed) returns `PARTIAL_LAUNCH` after the adapter cancels and reaps the commands already started.

## 11. AIEN direct-argv submission

AIEN submits the same request record, with `flags` bit 0 set, and fills `argv`, `assign` and `redir` directly. No shell string is built and the lexer, parser and expander are not called. The record then goes through the same `RESOLVE`, `PERM_CHECK`, `TASK_SPAWN` and cleanup path as a human pipeline, so the same binding check, receipts and limits apply. Rules: `builtin_id` must be 0 (else `REQ_FIELD`), counts must fit section 7.1, no NUL in any entry, `ncmds` 1 to 8. A model never receives an execution path that skips the effect boundary.

## 12. Cleanup

On normal end, `ERROR`, session reset or adapter shutdown, the adapter in this order: cancels still-running tasks of the in-flight pipeline (interrupt, then terminate after a bounded grace period), reaps every child, closes every stream and pipe end it opened (including ends held by a failed redirection), releases transient ids by advancing `session_epoch`, then clears the workspace. A partial failure never leaves a pipe end open in the parent, a zombie child, or an unreleased id. The core holds nothing to release.

## 13. Recording

Execution recording to Cortex is optional and policy-controlled, off unless policy enables it. Modes: 0 off, 1 redacted (default when enabled: `argv[0]`, argument count, argument lengths, builtin id, exit status, request digest; no argument values, no environment values, no stream contents), 2 full (only with an explicit policy grant; still excludes variables named by a secret list). Recording is history, not authority and not a gate. Mandatory security receipts (denials, grants used, revocation refusals) are produced by the effect boundary and are preserved whatever the recording mode.

## 14. Open items before freeze

1. OSC-EXT-BYTES lands (compiler: bytes and cells parameters, bounds, refusals) and the core compiles against it. Current compiler limits (32 functions per unit, 6 parameters, 480 virtual registers and 4096 instructions per function; omega `src/compiler/osc_ir.h:31-36` at `b980783`) are UNVERIFIED against the production core.
2. The Linux adapter consumes this ABI once end to end and the vectors pass in interpreter and native ARM64 modes.
3. Exact session cell indices are generated from one layout list with a shell script, plus a differential against a small C reference tokenizer.
4. Store location syntax and the native `RESOLVE` classes are decided with AIENOS release R1.1.
5. The numbering in 5.3 is a draft assignment; it freezes with the ABI.
6. Expected outputs in `vectors/` were authored from this text and no implementation has run them.

## 15. Conformance

A core conforms when, for every vector, it returns the status, request record, refusal code and offset in `vectors/expected.txt`, calling the entries as in section 5 with the vector's environment. An adapter conforms when it implements section 8 to 12 behavior against its platform and the adapter test suite passes; adapters are tested separately from the core. Vector format and the file list are defined in [`vectors/README.md`](vectors/README.md).
