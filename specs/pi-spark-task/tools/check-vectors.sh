#!/bin/bash
# check-vectors.sh: build the PST1 reference checker and check the vectors.
#
# Usage: check-vectors.sh [CC]        (default CC: cc)
#
# 1. Builds tools/pst_verify.c with warnings as errors (C99, libc only).
# 2. Regenerates the vectors into a scratch directory (pst_verify
#    --make-vectors) and requires them byte-identical to vectors/, so a stale
#    or hand-edited vector fails here.
# 3. Runs every vectors/expected.txt and vectors/sessions/expected.txt line
#    (re-encoding every accepted message, which must give the same bytes),
#    plus an ASan/UBSan build when the compiler supports it.
# 4. Runs the seeded random session test twice (same seed, same output).
# 5. Runs tools/mutate-verifier.sh: every check must be caught by a vector.
# Host-only check: no hardware. Shell and C only. Found by the PROTO-C-VECTORS
# gate (tests/gates/run.sh c-vectors) because its name matches check-*.sh.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -pedantic -o "$tmp/pst_verify" "$here/pst_verify.c"

mkdir -p "$tmp/regen/sessions"
"$tmp/pst_verify" --make-vectors "$tmp/regen"
ignore="-x .crumb -x .crumb.local -x .gitattributes"
if ! diff -r $ignore "$vec" "$tmp/regen" >/dev/null; then
    echo "PST1_VECTORS_STALE: vectors/ differs from pst_verify --make-vectors output" >&2
    diff -rq $ignore "$vec" "$tmp/regen" >&2 || true
    exit 1
fi
echo "PST1_VECTORS_REGEN identical"

"$tmp/pst_verify" --corpus "$vec"

if "$CC" -std=c99 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
        -o "$tmp/pst_verify_san" "$here/pst_verify.c" 2>/dev/null; then
    "$tmp/pst_verify_san" --corpus "$vec" | sed 's/^PST1_CONFORMANCE impl=c/PST1_CONFORMANCE impl=c-asan-ubsan/'
    test "${PIPESTATUS[0]}" -eq 0
else
    echo "PST1_SANITIZER NOT_RUN (compiler lacks -fsanitize=address,undefined)"
fi


# Seeded random sessions (spec section 10, aien-protocols-mv#32 item 4):
# reorder, drop and duplicate records of every accepted session. Each result
# is accepted or refused with a code; the same seed must give the same counts
# and the same digest of all verdict lines on two runs and under ASan/UBSan.
seed=${PST1_FUZZ_SEED:-20261016}
count=${PST1_FUZZ_COUNT:-20000}
"$tmp/pst_verify" --session-fuzz "$seed" "$count" "$vec"/sessions/ok-*.pss >"$tmp/fuzz1"
"$tmp/pst_verify" --session-fuzz "$seed" "$count" "$vec"/sessions/ok-*.pss >"$tmp/fuzz2"
cat "$tmp/fuzz1"
cmp -s "$tmp/fuzz1" "$tmp/fuzz2" || { echo "PST1_SESSION_FUZZ_NONDETERMINISTIC" >&2; exit 1; }
if [ -x "$tmp/pst_verify_san" ]; then
    "$tmp/pst_verify_san" --session-fuzz "$seed" "$count" "$vec"/sessions/ok-*.pss >"$tmp/fuzz3"
    cmp -s "$tmp/fuzz1" "$tmp/fuzz3" || { echo "PST1_SESSION_FUZZ_SANITIZER_DIFFERS" >&2; exit 1; }
    echo "PST1_SESSION_FUZZ repeat=identical sanitizer=identical"
else
    echo "PST1_SESSION_FUZZ repeat=identical sanitizer=NOT_RUN"
fi

bash "$here/mutate-verifier.sh" "$CC"
echo "PST1_VECTORS_PASS"
