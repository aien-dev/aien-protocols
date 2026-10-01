#!/bin/sh
# test-check-corpus.sh: prove check-corpus.sh ignores the crumb tool's files
# (.crumb, .crumb.local, exact names) and nothing else.
# Usage: test-check-corpus.sh [CC]   Copies specs/execution-transcript to a temp dir.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0

fresh() { rm -rf "$tmp/et"; cp -R "$here/.." "$tmp/et"; rm -f "$tmp/et/vectors/.crumb" "$tmp/et/vectors/.crumb.local"; }
runcheck() { sh -c 'bash "$1/tools/check-corpus.sh" "$2"' x "$tmp/et" "$CC" >"$tmp/out" 2>&1; }
expect() { # name, want (0|nz), then runcheck result
    if runcheck; then got=0; else got=nz; fi
    if [ "$got" = "$2" ]; then echo "ok   $1"; else echo "FAIL $1 (exit $got, wanted $2)"; tail -n 5 "$tmp/out"; fails=$((fails+1)); fi
}

fresh
expect baseline 0

# (a) kills: removing the -x .crumb exclusion (check would exit 1 as STALE).
fresh; printf 'crumb\n' >"$tmp/et/vectors/.crumb"
expect crumb-ignored 0
# (a2) kills: dropping only the .crumb.local exclusion.
fresh; printf 'local\n' >"$tmp/et/vectors/.crumb.local"
expect crumb-local-ignored 0

# (b) kills: widening the exclusion to a glob such as -x '.crumb*' or '*'.
fresh; printf 'x\n' >"$tmp/et/vectors/.crumbx"
expect near-name-still-fails nz
fresh; printf 'x\n' >"$tmp/et/vectors/stray.txt"
expect unknown-file-still-fails nz

# (c) kills: neutering the vector comparison (e.g. ignoring everything).
fresh
f="$tmp/et/vectors/f001.trn"
b=$(od -An -N1 -tu1 "$f" | tr -d ' ')
printf "\\$(printf '%03o' $((b ^ 1)))" | dd of="$f" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
expect mutated-golden-still-fails nz

[ "$fails" -eq 0 ] && echo "TEST_CHECK_CORPUS pass" || { echo "TEST_CHECK_CORPUS fail=$fails"; exit 1; }
