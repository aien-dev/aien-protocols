#!/bin/bash
# mutate-verifier.sh: show that every check in trn1_verify.c is exercised by
# the corpus. Builds one verifier per check with that check disabled
# (-DTRN1_MUTANT=K) and requires the corpus to report at least one miss.
# A mutant the corpus does not notice is a SURVIVOR and fails this script.
#
# Usage: mutate-verifier.sh [CC]
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
vec="$here/../vectors"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
names=$(sed -n '/CHK_MAGIC = 1/,/CHK_LAST/p' "$here/trn1_verify.c" | tr -d ' \n' | sed 's/CHK_MAGIC=1/CHK_MAGIC/; s/,CHK_LAST.*//' | tr ',' ' ')
test -n "$names" || { echo "cannot read the check list" >&2; exit 2; }
k=0 killed=0 survived=0
for name in $names; do
    k=$((k + 1))
    "$CC" -std=c99 -O1 -w -DTRN1_MUTANT=$k -o "$tmp/m$k" "$here/trn1_verify.c"
    if "$tmp/m$k" --corpus "$vec" >"$tmp/out$k" 2>&1; then
        echo "SURVIVOR $k $name"
        survived=$((survived + 1))
    else
        echo "killed $k $name: $(grep -c '^MISMATCH' "$tmp/out$k") corpus line(s) differ"
        killed=$((killed + 1))
    fi
done
echo "TRN1_VERIFIER_MUTANTS total=$k killed=$killed survived=$survived"
test "$survived" -eq 0 && test "$k" -gt 0
