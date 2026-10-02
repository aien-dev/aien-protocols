#!/bin/bash
# make-golden.sh OUT_DIR: write the VC1 golden vectors (hex files) and
# expected.txt from explicit hex fragments. It does NOT use the C tool, so the
# vectors are built independently of the encoder under test. Shell + coreutils
# + xxd only.
set -eu
export LC_ALL=C
out=${1:?usage: make-golden.sh OUT_DIR}
mkdir -p "$out"

hexs() { printf '%s' "$1" | xxd -p -c 99999 | tr -d '\n'; }          # ASCII -> hex
rep()  { local i s=""; for ((i = 0; i < 32; i++)); do s+="$1"; done; printf '%s' "$s"; }  # byte -> 32 bytes
u32()  { printf '%08x' "$1"; }
str()  { printf '%016x%s' "${#1}" "$(hexs "$1")"; }                    # u64 BE length + bytes
TAG=$(hexs "AIEN_VERIFIED_CRUMB_V1")

# vc VERSION SEM CON KIND SRC "REALS" "DEPS" RECEIPT PROFILE VER ROOT "EXPORTS" "CAPS"
#   ids are one byte token (e.g. 11) repeated 32 times; KIND = one byte token
#   (01 source, 02 IR); REALS = tokens;
#   DEPS = tokens "sem/contract" ; EXPORTS and CAPS = ASCII words.
vc() {
    local ver=$1 sem=$2 con=$3 kind=$4 src=$5 reals=$6 deps=$7 rcpt=$8 prof=$9 pver=${10} root=${11} exps=${12} caps=${13}
    local s="$TAG$(u32 "$ver")$(rep "$sem")$(rep "$con")$kind$(rep "$src")" r d e c n
    n=0; for r in $reals; do n=$((n + 1)); done; s+=$(u32 $n)
    for r in $reals; do s+=$(rep "$r"); done
    n=0; for d in $deps; do n=$((n + 1)); done; s+=$(u32 $n)
    for d in $deps; do s+="$(rep "${d%/*}")$(rep "${d#*/}")"; done
    s+="$(rep "$rcpt")$(str "$prof")$(str "$pver")$(rep "$root")"
    n=0; for e in $exps; do n=$((n + 1)); done; s+=$(u32 $n)
    for e in $exps; do s+=$(str "$e"); done
    n=0; for c in $caps; do n=$((n + 1)); done; s+=$(u32 $n)
    for c in $caps; do s+=$(str "$c"); done
    printf '%s' "$s"
}
emit() { printf '%s\n' "$2" > "$out/$1.hex"; }

: > "$out/expected.txt"
# expected ACCEPT ids are computed with sha256sum over the raw bytes
# (independent of the C tool's own SHA-256).
accept() {
    emit "$1" "$2"
    local id; id=$(printf '%s' "$2" | xxd -r -p | sha256sum | cut -d' ' -f1)
    echo "$1 ACCEPT $id" >> "$out/expected.txt"
}
refuse() { emit "$1" "$2"; echo "$1 REFUSE $3" >> "$out/expected.txt"; }

P=test-profile
accept v01_minimal       "$(vc 1 11 22 01 33 "44" "" 55 $P 1.0.0 66 "" "")"
accept v02_deps          "$(vc 1 11 22 01 33 "44 45" "a1/b1 a2/b2" 55 $P 1.0.0 66 "main" "")"
accept v03_capabilities  "$(vc 1 12 22 01 33 "44" "a1/b1" 56 $P 1.0.0 67 "add sub" "cap.clock.read cap.fs.read")"

refuse r01_duplicate_dep      "$(vc 1 11 22 01 33 "44" "a1/b1 a1/b2" 55 $P 1.0.0 66 "" "")" DUPLICATE_DEPENDENCY
refuse r02_unsorted_deps      "$(vc 1 11 22 01 33 "44" "a2/b2 a1/b1" 55 $P 1.0.0 66 "" "")" UNSORTED_DEPENDENCIES
refuse r03_zero_receipt_id    "$(vc 1 11 22 01 33 "44" "" 00 $P 1.0.0 66 "" "")" MISSING_RECEIPT
refuse r04_self_dependency    "$(vc 1 11 22 01 33 "44" "11/b1" 55 $P 1.0.0 66 "" "")" DEPENDENCY_CYCLE
refuse r05_trailing_byte      "$(vc 1 11 22 01 33 "44" "" 55 $P 1.0.0 66 "" "")00" TRAILING_BYTES
refuse r06_unknown_version    "$(vc 2 11 22 01 33 "44" "" 55 $P 1.0.0 66 "" "")" UNKNOWN_FORMAT_VERSION
v=$(vc 1 11 22 01 33 "44" "" 55 $P 1.0.0 66 "" "")
refuse r07_truncated          "${v%??}" TRUNCATED
refuse r08_bad_domain_tag     "$(printf '%s' "$v" | sed 's/^\(.\{42\}\)../\10a/')" BAD_DOMAIN_TAG
refuse r09_unsorted_exports   "$(vc 1 11 22 01 33 "44" "" 55 $P 1.0.0 66 "sub add" "")" NONCANONICAL_SET

# digest_kind: 0x02 (IR) with the same digest bytes as v01 must give a different id
accept v04_ir_kind            "$(vc 1 11 22 02 33 "44" "" 55 $P 1.0.0 66 "" "")"
refuse r10_bad_digest_kind    "$(vc 1 11 22 03 33 "44" "" 55 $P 1.0.0 66 "" "")" BAD_DIGEST_KIND
refuse r11_zero_id            "$(vc 1 00 22 01 33 "44" "" 55 $P 1.0.0 66 "" "")" ZERO_ID
refuse r12_bad_string         "$(vc 1 11 22 01 33 "44" "" 55 "bad profile" 1.0.0 66 "" "")" BAD_STRING
# 257 realizations declared (limit 256): refused at the count, before any body
refuse r13_too_many_entries   "$TAG$(u32 1)$(rep 11)$(rep 22)01$(rep 33)$(u32 257)" TOO_MANY_ENTRIES
