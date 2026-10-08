#!/bin/bash
# check-vectors.sh: regenerate the vectors into a scratch directory, require
# them byte-identical to the committed ones, then run the reference checker
# over every line of vectors/expected.txt. Exit 1 on any difference.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bash "$here/make-vectors.sh" "$tmp/vectors" "$tmp/keys"
# the committed keys must also be the regenerated ones
diff -r "$tmp/keys" "$here/../keys" >/dev/null || { echo "OSC_UNIT_KEYS_STALE" >&2; exit 1; }
diff -r "$tmp/vectors" "$here/../vectors" -x README.md >/dev/null || { echo "OSC_UNIT_VECTORS_STALE" >&2; diff -rq "$tmp/vectors" "$here/../vectors" -x README.md >&2 || true; exit 1; }
echo "OSC_UNIT_REGEN identical"
fail=0; n=0
while read -r name mode domains anchors rest; do
    case $name in '#'*|'') continue ;; esac
    got=$(bash "$here/osc-unit-check.sh" "$here/../vectors/$name" "$mode" "$domains" "$anchors")
    n=$((n + 1))
    if [ "$got" != "$rest" ]; then echo "MISMATCH $name: want '$rest' got '$got'" >&2; fail=1; fi
done <"$here/../vectors/expected.txt"
while read -r name mode domains anchors lname rest; do
    case $name in '#'*|'') continue ;; esac
    got=$(bash "$here/osc-unit-check.sh" "$here/../vectors/$name" "$mode" "$domains" "$anchors" "$lname")
    n=$((n + 1))
    if [ "$got" != "$rest" ]; then echo "MISMATCH lookup $name $lname: want '$rest' got '$got'" >&2; fail=1; fi
done <"$here/../vectors/lookups.txt"
while read -r name mode domains anchors state rest; do
    case $name in '#'*|'') continue ;; esac
    case $state in
    gens=*) got=$(OSC_STATE_GENS="${state#gens=}" bash "$here/osc-unit-check.sh" "$here/../vectors/$name" "$mode" "$domains" "$anchors") ;;
    noreserve) got=$(OSC_STATE_NORESERVE=1 bash "$here/osc-unit-check.sh" "$here/../vectors/$name" "$mode" "$domains" "$anchors") ;;
    esac
    n=$((n + 1))
    if [ "$got" != "$rest" ]; then echo "MISMATCH state $name $state: want '$rest' got '$got'" >&2; fail=1; fi
done <"$here/../vectors/state.txt"
cc -std=c99 -O2 -Wall -Wextra -Werror -o "$tmp/launch" "$here/osc-launch-check.c"
while read -r kinds args rest; do
    case $kinds in '#'*|'') continue ;; esac
    got=$("$tmp/launch" "$kinds" "$args")
    n=$((n + 1))
    if [ "$got" != "$rest" ]; then echo "MISMATCH launch $kinds $args: want '$rest' got '$got'" >&2; fail=1; fi
done <"$here/../vectors/launch.txt"
[ $fail -eq 0 ] || exit 1
echo "OSC_UNIT_VECTORS_PASS $n vectors"
