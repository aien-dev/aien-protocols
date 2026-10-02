#!/bin/bash
# check-golden.sh [CC]: prove the VC1 golden corpus and the C checker agree.
#
#  1. golden/ is byte-identical to make-golden.sh output (ignoring the crumb
#     tool's .crumb and .crumb.local files).
#  2. vc1-check builds with warnings as errors (and under ASan/UBSan if the
#     compiler has it) and passes every line of golden/expected.txt.
#  3. Every ACCEPT id is recomputed with sha256sum over the raw bytes, a hash
#     implementation independent of the C tool.
#  4. Vector mutants (flip a byte, reorder deps, drop the domain tag) must be
#     detected: the checker's answer must differ from the golden expectation.
#  5. Checker mutants (-DVC1_MUTANT=1..9) must each make the corpus FAIL.
# Host-only. Shell, xxd, sha256sum and a C99 compiler. No Python.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
gold="$here/../golden"
CC=${1:-cc}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bash "$here/make-golden.sh" "$tmp/regen"
if ! diff -r -x .crumb -x .crumb.local "$gold" "$tmp/regen" >/dev/null; then
    echo "VC1_GOLDEN_STALE: golden/ differs from make-golden.sh output" >&2
    diff -rq -x .crumb -x .crumb.local "$gold" "$tmp/regen" >&2 || true
    exit 1
fi
echo "VC1_GOLDEN_REGEN identical"

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -o "$tmp/vc1-check" "$here/vc1-check.c"
"$tmp/vc1-check" --corpus "$gold"
if "$CC" -std=c99 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all \
        -o "$tmp/vc1-check-san" "$here/vc1-check.c" 2>/dev/null; then
    "$tmp/vc1-check-san" --corpus "$gold" | sed 's/impl=c /impl=c-asan-ubsan /'
else
    echo "VC1_SANITIZER NOT_RUN (compiler lacks -fsanitize=address,undefined)"
fi

# 3. independent hash cross-check
n=0
while read -r name verb arg; do
    [ "$verb" = ACCEPT ] || continue
    want=$(xxd -r -p "$gold/$name.hex" | sha256sum | cut -d' ' -f1)
    got=$("$tmp/vc1-check" "$gold/$name.hex" | cut -d' ' -f2)
    if [ "$want" != "$arg" ] || [ "$got" != "$arg" ]; then
        echo "VC1_HASH_MISMATCH $name expected=$arg sha256sum=$want tool=$got" >&2; exit 1
    fi
    n=$((n + 1))
done < "$gold/expected.txt"
echo "VC1_INDEPENDENT_SHA256 ids=$n agree"
# same digest bytes, different digest_kind: ids must differ
id1=$(grep "^v01_minimal " "$gold/expected.txt" | cut -d" " -f3); id4=$(grep "^v04_ir_kind " "$gold/expected.txt" | cut -d" " -f3)
[ "$id1" != "$id4" ] || { echo "VC1_KIND_NOT_IN_ID" >&2; exit 1; }
echo "VC1_DIGEST_KIND_IN_ID v01(source) != v04(ir)"

# 4. vector mutants, applied to v02_deps (hex string surgery, 2 hex chars per byte)
v=$(tr -d '\n' < "$gold/v02_deps.hex")
exp=$(grep '^v02_deps ' "$gold/expected.txt" | cut -d' ' -f2-)
tag=44              # domain tag is 22 bytes = 44 hex chars
sem=$((tag + 8))    # semantic_id starts after tag and 4-byte version
deps=$((tag + 8 + 3 * 64 + 2 + 8 + 2 * 64 + 8))  # first dep entry: tag, version, 3 ids, digest_kind byte, realization count, 2 realizations, dep count
flip=$(printf '%s' "$v" | sed "s/^\(.\{$sem\}\)../\1ee/")
d1=${v:$deps:128}; d2=${v:$((deps + 128)):128}
swap="${v:0:$deps}$d2$d1${v:$((deps + 256))}"
notag=${v:$tag}
mut=0
for m in flip swap notag; do
    case $m in flip) h=$flip;; swap) h=$swap;; notag) h=$notag;; esac
    [ "$h" != "$v" ] || { echo "VC1_MUTANT_NOOP $m" >&2; exit 2; }
    printf '%s\n' "$h" > "$tmp/m.hex"
    set +e; got=$("$tmp/vc1-check" "$tmp/m.hex" | sed 's/ @.*//'); set -e
    if [ "$got" = "$exp" ]; then echo "VC1_VECTOR_MUTANT_SURVIVED $m" >&2; exit 1; fi
    echo "vector mutant $m -> $got (golden: ACCEPT ${exp#ACCEPT }) detected"
    mut=$((mut + 1))
done
echo "VC1_VECTOR_MUTANTS detected=$mut/3"

# 5. checker mutants
surv=0
for k in 1 2 3 4 5 6 7 8 9; do
    "$CC" -std=c99 -O2 -DVC1_MUTANT=$k -o "$tmp/mut$k" "$here/vc1-check.c"
    if "$tmp/mut$k" --corpus "$gold" >"$tmp/mut$k.out" 2>&1; then
        echo "VC1_CHECKER_MUTANT_SURVIVED $k" >&2; surv=$((surv + 1))
    else
        echo "checker mutant $k: $(tail -n 1 "$tmp/mut$k.out") (killed)"
    fi
done
[ "$surv" -eq 0 ] || exit 1
echo "VC1_CHECKER_MUTANTS killed=9/9"
echo "VC1_GOLDEN_CHECK PASS"
