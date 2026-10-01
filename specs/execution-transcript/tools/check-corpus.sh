#!/bin/bash
# check-corpus.sh: build the C reference verifier and check the TRN1 corpus.
#
# Usage: check-corpus.sh [CC]        (default CC: cc)
#
# 1. Regenerates the corpus into a temporary directory with make-corpus.sh
#    and requires it to be byte-identical to vectors/, .gitattributes included
#    (a stale or hand-edited corpus fails here).
# 2. Builds trn1_verify.c with warnings as errors, plus an ASan/UBSan build
#    when the compiler supports it.
# 3. Runs every expected.txt and compare.txt line; prints
#    TRN1_CONFORMANCE impl=c pass=N fail=M and exits non-zero on any miss.
# Host-only check: no hardware, no QEMU. Shell and C only.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bash "$here/make-corpus.sh" "$tmp/regen" >/dev/null
# The comparison is the whole directory, byte for byte, including
# vectors/.gitattributes (make-corpus.sh emits it). Before trusting it, prove
# it catches drift on a copy of the regenerated corpus (counterexamples):
#   a) one bit flipped in one vector must differ;
#   b) a vector missing must differ;
#   c) the line-ending pin (.gitattributes) removed must differ.
first=$(ls "$tmp/regen"/*.trn | head -n 1)
test -s "$first" || { echo "TRN1_CORPUS_SELFTEST: no non-empty vector to alter" >&2; exit 2; }
for cx in flip drop attr; do
    rm -rf "$tmp/cx" && cp -r "$tmp/regen" "$tmp/cx"
    f="$tmp/cx/$(basename "$first")"
    case $cx in
    flip) b=$(od -An -N1 -tu1 "$f" | tr -d ' ')
          printf "\\$(printf '%03o' $((b ^ 1)))" | dd of="$f" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null ;;
    drop) rm -f "$f" ;;
    attr) rm -f "$tmp/cx/.gitattributes" ;;
    esac
    if diff -r "$tmp/cx" "$tmp/regen" >/dev/null; then
        echo "TRN1_CORPUS_SELFTEST: counterexample '$cx' not detected" >&2
        exit 2
    fi
done
echo "TRN1_CORPUS_SELFTEST counterexamples=3 detected=3"
if ! diff -r "$vec" "$tmp/regen" >/dev/null; then
    echo "TRN1_CORPUS_STALE: vectors/ differs from make-corpus.sh output" >&2
    diff -rq "$vec" "$tmp/regen" >&2 || true
    exit 1
fi
echo "TRN1_CORPUS_REGEN identical"

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -o "$tmp/trn1_verify" "$here/trn1_verify.c"
"$tmp/trn1_verify" --corpus "$vec"

if "$CC" -std=c99 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
        -o "$tmp/trn1_verify_san" "$here/trn1_verify.c" 2>/dev/null; then
    "$tmp/trn1_verify_san" --corpus "$vec" | sed 's/^TRN1_CONFORMANCE impl=c/TRN1_CONFORMANCE impl=c-asan-ubsan/'
    test "${PIPESTATUS[0]}" -eq 0
else
    echo "TRN1_SANITIZER NOT_RUN (compiler lacks -fsanitize=address,undefined)"
fi
