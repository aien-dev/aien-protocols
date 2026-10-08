#!/bin/bash
# osc-unit-check.sh: reference admission checker for OSC unit artifact
# container v1 (../OSC_UNIT_ARTIFACT.md section 8). Shell, xxd, sha256sum and
# openssl (Ed25519) only. No Python.
#
# Usage: osc-unit-check.sh UNIT MODE DOMAINS ANCHORS
#   MODE     release | qualification
#   DOMAINS  comma list of capability domains the loader supports, e.g. 1 or 1,2
#   ANCHORS  trust anchors present: "-" none, or letters T (TEST anchor),
#            O (OWNER anchor); anchor keys are ../keys/test1.pub and
#            ../keys/owner1.pub (throwaway TEST keys)
# Prints one line: ACCEPT unit_id=<hex> | REFUSED <CODE_NAME> <number>
# Exit 0 always for a verdict; 2 on usage error.
set -u
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
f=${1:?UNIT}; mode=${2:?MODE}; domains=${3:?DOMAINS}; anchors=${4:?ANCHORS}

# loader profile (section 8.1)
SUPPORTED_UNIT_FORMATS=" 1 2 3 4 5 "
PROVIDED_ABI=1

fail() { echo "REFUSED $1 $2"; exit 0; }
# lehex FILE OFF N : little-endian field as big-endian hex digits
lehex() {
    local h r="" i
    h=$(xxd -p -s "$2" -l "$3" "$1" | tr -d '\n')
    for ((i = ${#h} - 2; i >= 0; i -= 2)); do r+=${h:i:2}; done
    echo "$r"
}
# le FILE OFF N : little-endian unsigned (N <= 4) as decimal
le() { echo $((16#$(lehex "$1" "$2" "$3"))); }
hexat() { xxd -p -s "$2" -l "$3" "$1" | tr -d '\n'; }
sha_range() { tail -c +$(($2 + 1)) "$1" | head -c "$3" | sha256sum | cut -d' ' -f1; }
iszero() { # FILE OFF N
    [ "$(hexat "$1" "$2" "$3")" = "$(printf '%*s' $(($3 * 2)) '' | tr ' ' 0)" ]
}
align16() { echo $((($1 + 15) / 16 * 16)); }

len=$(stat -c %s "$f")
# 1 TRUNCATED
[ "$len" -ge 128 ] || fail TRUNCATED 1
# 2 BAD_MAGIC
[ "$(hexat "$f" 0 8)" = "4f5343554e495400" ] || fail BAD_MAGIC 2
# 3 CONTAINER_VERSION
[ "$(le "$f" 8 2)" -eq 1 ] || fail CONTAINER_VERSION 3
# 4 HEADER_FIELD
if [ "$(le "$f" 10 2)" -ne 128 ] || [ "$(le "$f" 24 4)" -ne 128 ] || [ "$(le "$f" 28 2)" -ne 4 ] ||
    [ "$(le "$f" 30 2)" -ne 48 ] || ! iszero "$f" 34 2 || ! iszero "$f" 50 2 || ! iszero "$f" 52 4 ||
    ! iszero "$f" 60 4 || ! iszero "$f" 96 32; then
    fail HEADER_FIELD 4
fi
# 5 UNIT_FORMAT
ufv=$(le "$f" 12 2)
case "$SUPPORTED_UNIT_FORMATS" in *" $ufv "*) ;; *) fail UNIT_FORMAT 5 ;; esac
# 6 ABI_VERSION
[ "$(le "$f" 14 2)" -eq "$PROVIDED_ABI" ] || fail ABI_VERSION 6
# 7 UNKNOWN_FLAGS
[ "$(le "$f" 16 4)" -eq 0 ] || fail UNKNOWN_FLAGS 7
# 9 TOTAL_LENGTH, 1 TRUNCATED, 8 TRAILING_BYTES
total=$(le "$f" 20 4)
{ [ "$total" -ge 384 ] && [ "$total" -le 2097152 ]; } || fail TOTAL_LENGTH 9
[ "$len" -ge "$total" ] || fail TRUNCATED 1
[ "$len" -le "$total" ] || fail TRAILING_BYTES 8
sigoff=$((total - 64))

# section table: 4 entries of 48 bytes at 128
off=(0 0 0 0 0); slen=(0 0 0 0 0); shash=("" "" "" "" "")
for k in 1 2 3 4; do
    e=$((128 + (k - 1) * 48))
    [ "$(le "$f" "$e" 2)" -eq "$k" ] || fail SECTION_TABLE 10
    [ "$(le "$f" $((e + 2)) 2)" -eq 0 ] || fail SECTION_TABLE 10
    iszero "$f" $((e + 12)) 4 || fail SECTION_TABLE 10
    off[$k]=$(le "$f" $((e + 4)) 4)
    slen[$k]=$(le "$f" $((e + 8)) 4)
    shash[$k]=$(hexat "$f" $((e + 16)) 32)
done
# 11 SECTION_BOUNDS
for k in 1 2 3 4; do
    [ $((off[k] + slen[k])) -le "$sigoff" ] && [ "${off[$k]}" -ge 320 ] || fail SECTION_BOUNDS 11
done
# 12 SECTION_OVERLAP (pairwise, any order)
for a in 1 2 3 4; do
    for b in 1 2 3 4; do
        [ "$a" -lt "$b" ] || continue
        if [ "${slen[$a]}" -gt 0 ] && [ "${slen[$b]}" -gt 0 ] &&
            [ "${off[$a]}" -lt $((off[b] + slen[b])) ] && [ "${off[$b]}" -lt $((off[a] + slen[a])) ]; then
            fail SECTION_OVERLAP 12
        fi
    done
done
# 13 SECTION_LAYOUT: canonical offsets, zero gaps, signature immediately after last
pos=320
for k in 1 2 3 4; do
    want=$(align16 "$pos")
    [ "${off[$k]}" -eq "$want" ] || fail SECTION_LAYOUT 13
    if [ "$want" -gt "$pos" ]; then iszero "$f" "$pos" $((want - pos)) || fail SECTION_LAYOUT 13; fi
    pos=$((want + slen[k]))
done
[ "$pos" -eq "$sigoff" ] || fail SECTION_LAYOUT 13
# 14 LIMIT_EXCEEDED
nfn=$(le "$f" 32 2); stack=$(le "$f" 36 4); ticks=$(lehex "$f" 40 8); pools=$(le "$f" 48 2)
[ "$nfn" -ge 1 ] && [ "$nfn" -le 32 ] || fail LIMIT_EXCEEDED 14
{ [ "$stack" -ge 4096 ] && [ "$stack" -le 1048576 ] && [ $((stack % 16)) -eq 0 ]; } || fail LIMIT_EXCEEDED 14
{ [ $((16#$ticks)) -ge 1 ] && [ $((16#$ticks)) -le 1000000000 ]; } || fail LIMIT_EXCEEDED 14
[ "$pools" -le 64 ] || fail LIMIT_EXCEEDED 14
{ [ "${slen[1]}" -ge 8 ] && [ "${slen[1]}" -le 1048576 ]; } || fail LIMIT_EXCEEDED 14
{ [ "${slen[2]}" -ge 4 ] && [ "${slen[2]}" -le 262144 ] && [ $((slen[2] % 4)) -eq 0 ]; } || fail LIMIT_EXCEEDED 14
[ "${slen[3]}" -eq $((nfn * 32)) ] || fail LIMIT_EXCEEDED 14
[ "${slen[4]}" -ge 8 ] || fail LIMIT_EXCEEDED 14
ncap=$(le "$f" "${off[4]}" 2)
[ "$ncap" -le 16 ] || fail LIMIT_EXCEEDED 14
[ "${slen[4]}" -eq $((8 + ncap * 64)) ] || fail LIMIT_EXCEEDED 14
# 15..18 section hashes
names=(x IR_HASH_MISMATCH CODE_HASH_MISMATCH ENTRY_HASH_MISMATCH CAPS_HASH_MISMATCH)
for k in 1 2 3 4; do
    [ "$(sha_range "$f" "${off[$k]}" "${slen[$k]}")" = "${shash[$k]}" ] || fail "${names[$k]}" $((14 + k))
done
# 19 IR_MALFORMED
[ "$(hexat "$f" "${off[1]}" 7)" = "4f534331495200" ] || fail IR_MALFORMED 19
[ "$(le "$f" $((off[1] + 7)) 1)" -eq "$ufv" ] || fail IR_MALFORMED 19
# 20 ENTRY_TABLE
prev=-1
for ((i = 0; i < nfn; i++)); do
    e=$((off[3] + i * 32))
    [ "$(le "$f" "$e" 2)" -eq "$i" ] || fail ENTRY_TABLE 20
    nregs=$(le "$f" $((e + 2)) 1); ret=$(le "$f" $((e + 3)) 1)
    [ "$nregs" -le 6 ] || fail ENTRY_TABLE 20
    [ "$ret" -le 9 ] || fail ENTRY_TABLE 20
    iszero "$f" $((e + 10)) 2 || fail ENTRY_TABLE 20
    for ((r = 0; r < 6; r++)); do
        kind=$(le "$f" $((e + 4 + r)) 1)
        if [ "$r" -ge "$nregs" ]; then [ "$kind" -eq 0 ] || fail ENTRY_TABLE 20; continue; fi
        case $kind in
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9) ;;
        11 | 12)
            [ $((r + 1)) -lt "$nregs" ] || fail ENTRY_TABLE 20
            [ "$(le "$f" $((e + 4 + r + 1)) 1)" -eq 5 ] || fail ENTRY_TABLE 20
            ;;
        *) fail ENTRY_TABLE 20 ;;
        esac
    done
    co=$(le "$f" $((e + 12)) 4)
    { [ $((co % 4)) -eq 0 ] && [ "$co" -lt "${slen[2]}" ] && [ "$co" -gt "$prev" ]; } || fail ENTRY_TABLE 20
    prev=$co
done
# 21 CAPS_TABLE
iszero "$f" $((off[4] + 2)) 6 || fail CAPS_TABLE 21
prevkey=""
for ((i = 0; i < ncap; i++)); do
    e=$((off[4] + 8 + i * 64))
    kind=$(le "$f" "$e" 2); cflags=$(le "$f" $((e + 2)) 2); rid=$(le "$f" $((e + 4)) 4)
    rights=$(le "$f" $((e + 8)) 4); bk=$(le "$f" $((e + 12)) 4); mops=$(le "$f" $((e + 16)) 4)
    iszero "$f" $((e + 20)) 4 || fail CAPS_TABLE 21
    mbytes=$(lehex "$f" $((e + 24)) 8); boff=$(lehex "$f" $((e + 32)) 8); blen=$(lehex "$f" $((e + 40)) 8)
    dom=$(le "$f" $((e + 48)) 2); dflags=$(le "$f" $((e + 50)) 2)
    { [ "$kind" -eq 2 ] || [ "$kind" -eq 3 ]; } || fail CAPS_TABLE 21
    [ "$cflags" -eq 0 ] && [ "$rid" -ne 0 ] || fail CAPS_TABLE 21
    { [ "$rights" -ne 0 ] && [ $((rights & ~63)) -eq 0 ]; } || fail CAPS_TABLE 21
    [ "$mops" -gt 0 ] || fail CAPS_TABLE 21
    [ "$((16#$mbytes))" -gt 0 ] || fail CAPS_TABLE 21
    if [ "$kind" -eq 3 ]; then
        [ "$bk" -eq 1 ] && [ $((16#$blen)) -gt 0 ] && [ $((16#$mbytes)) -le $((16#$blen)) ] || fail CAPS_TABLE 21
    else
        [ "$bk" -eq 2 ] && [ $((16#$boff)) -eq 0 ] && [ $((16#$blen)) -eq 0 ] || fail CAPS_TABLE 21
    fi
    { [ "$dom" -eq 1 ] || [ "$dom" -eq 2 ]; } || fail CAPS_TABLE 21
    [ "$dflags" -eq 0 ] || fail CAPS_TABLE 21
    iszero "$f" $((e + 52)) 4 || fail CAPS_TABLE 21
    key=$(printf '%02d%02d%010d' "$dom" "$kind" "$rid")
    if [ -n "$prevkey" ] && ! [[ "$key" > "$prevkey" ]]; then fail CAPS_TABLE 21; fi
    prevkey=$key
done
# 22 SIGNER_CLASS, 23 SIGNATURE_ALGORITHM
class=$(le "$f" 56 2)
{ [ "$class" -eq 1 ] || [ "$class" -eq 2 ]; } || fail SIGNER_CLASS 22
[ "$(le "$f" 58 2)" -eq 1 ] || fail SIGNATURE_ALGORITHM 23
# 24 TEST_SIGNER_IN_RELEASE
if [ "$class" -eq 1 ] && [ "$mode" = release ]; then fail TEST_SIGNER_IN_RELEASE 24; fi
# 25 UNTRUSTED_SIGNER: key only from the local anchor set, by fingerprint
fp=$(hexat "$f" 64 32)
pubfile=""
if [ "$class" -eq 1 ]; then want=T; pubfile=$here/../keys/test1.pub; else want=O; pubfile=$here/../keys/owner1.pub; fi
case "$anchors" in *"$want"*) ;; *) fail UNTRUSTED_SIGNER 25 ;; esac
pub=$(tr -d '\n' <"$pubfile")
[ "$(printf '%s' "$pub" | xxd -r -p | sha256sum | cut -d' ' -f1)" = "$fp" ] || fail UNTRUSTED_SIGNER 25
# 26 BAD_SIGNATURE: Ed25519 (RFC 8032, pure) over the domain-separated digest
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
digest=$(head -c 320 "$f" | { printf 'AIENOS-OSC-UNIT-V1\0'; cat; } | sha256sum | cut -d' ' -f1)
{ printf 'AIENOS-OSC-UNIT-SIGNATURE-V1\0'; printf '%s' "$digest" | xxd -r -p; } >"$tmp/msg"
{ printf '302a300506032b6570032100'; printf '%s' "$pub"; } | xxd -r -p >"$tmp/pub.der"
tail -c 64 "$f" >"$tmp/sig"
openssl pkeyutl -verify -pubin -inkey "$tmp/pub.der" -keyform DER -rawin -in "$tmp/msg" -sigfile "$tmp/sig" >/dev/null 2>&1 ||
    fail BAD_SIGNATURE 26
# 27 CAP_DOMAIN_UNSUPPORTED, 28 CAP_GEN_NOT_REPRESENTABLE
for ((i = 0; i < ncap; i++)); do
    e=$((off[4] + 8 + i * 64))
    dom=$(le "$f" $((e + 48)) 2)
    case ",$domains," in *",$dom,"*) ;; *) fail CAP_DOMAIN_UNSUPPORTED 27 ;; esac
    if [ "$dom" -eq 1 ]; then
        g=$(lehex "$f" $((e + 56)) 8)
        [ "${g:0:8}" = 00000000 ] || fail CAP_GEN_NOT_REPRESENTABLE 28
    fi
done
echo "ACCEPT unit_id=${shash[1]}"
