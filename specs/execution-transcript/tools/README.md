# TRN1 tools

All scripts here are host-only (no hardware, no QEMU) and use shell plus
coreutils and a C99 compiler. No Python.

**Run them with bash.** `make-corpus.sh`, `check-corpus.sh` and
`mutate-verifier.sh` are bash scripts (`#!/bin/bash`; `make-corpus.sh` uses bash arrays and C-style `for` loops,
`check-corpus.sh` uses `${PIPESTATUS[0]}`). On systems where `/bin/sh` is
dash, `sh check-corpus.sh` fails with a syntax error that says nothing about
the corpus. `test-check-corpus.sh` is POSIX sh and calls `bash` itself, so
either `sh` or `bash` works for it.

| Script | Run as | What it does |
|---|---|---|
| `make-corpus.sh OUT_DIR` | `bash tools/make-corpus.sh vectors` | regenerates every vector and manifest (`expected.txt`, `compare.txt`, `join.txt`, `.gitattributes`) from the spec tables |
| `check-corpus.sh [CC]` | `bash tools/check-corpus.sh` | regenerates into a temp dir, requires it byte-identical to `vectors/`, builds `trn1_verify.c` (warnings as errors, plus ASan/UBSan when available) and checks every `expected.txt` and `compare.txt` line |
| `test-check-corpus.sh [CC]` | `sh tools/test-check-corpus.sh` | proves `check-corpus.sh` ignores only the crumb tool's `.crumb` and `.crumb.local` files |
| `mutate-verifier.sh [CC]` | `bash tools/mutate-verifier.sh` | builds one verifier per check with that check disabled; any mutant the corpus does not catch is a SURVIVOR and fails the run |
| `trn1_verify.c` | `cc -std=c99 -o trn1_verify tools/trn1_verify.c` | reference verifier: `FILE`, `--compare EXP ACT`, `--corpus DIR` |

`vectors/join.txt` is not read by any tool here. It lists the causal-join
refusals a joiner must produce (spec section 5.5) and stays NOT_RUN until
one exists.
