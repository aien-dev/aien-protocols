#!/bin/bash
# make-vectors.sh: regenerate the OSC unit artifact container v1 conformance
# vectors. Contract: ../OSC_UNIT_ARTIFACT.md. Shell, xxd, sha256sum and
# openssl (Ed25519) only. No Python.
#
# Usage: make-vectors.sh OUT_DIR [KEYS_DIR]
#   OUT_DIR   normally specs/osc-unit-artifact/vectors
#   KEYS_DIR  where to write the two public keys (default ../keys)
#
# Inputs (../src): min.osc, and its real compiler output min.ir (the canonical
# IR, version byte 5) and min.code (A64 bytes), produced by omega `oscc` at
# osh/osc-ext-bytes d64ccb3 (ir_sha256 and code_sha256 as `oscc` prints them).
#
# Keys: two THROWAWAY TEST keys derived from fixed labels (so vectors are
# reproducible). They protect nothing and are not any AIEN key. Never reuse
# them. "test1" signs class TEST; "owner1" is a TEST key standing in for an
# OWNER key in OWNER-class vectors.
#
# Every structural mutant is re-signed so the refusal is attributable to the
# intended check, not to a stale signature.
set -eu
export LC_ALL=C
here=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?OUT_DIR}
KEYS=${2:-$here/../keys}
SRC=$here/../src
mkdir -p "$OUT" "$KEYS"
rm -f "$OUT"/*.unit
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# ---- byte helpers ---------------------------------------------------------
u8() { printf "\\x$(printf %02x "$1")"; }
le16() { u8 $(($1 & 255)); u8 $((($1 >> 8) & 255)); }
le32() { for s in 0 8 16 24; do u8 $((($1 >> s) & 255)); done; }
le64() { le32 $(($1 & 0xffffffff)); le32 $((($1 >> 32) & 0xffffffff)); }
hex2bin() { printf '%s' "$1" | xxd -r -p; }
zeros() { head -c "$1" /dev/zero; }
sha() { sha256sum | cut -d' ' -f1; }
align16() { echo $((($1 + 15) / 16 * 16)); }
# patch FILE OFFSET HEX... : copy of FILE with bytes replaced at OFFSET
patch() {
    local f=$1 off=$2
    shift 2
    head -c "$off" "$f"
    for h in "$@"; do printf "\\x$h"; done
    tail -c +$((off + 1 + $#)) "$f"
}

# ---- throwaway TEST keys --------------------------------------------------
mkkey() { # NAME LABEL -> $tmp/NAME.pem, $KEYS/NAME.pub (64 hex chars)
    local seed
    seed=$(printf '%s' "$2" | sha)
    { printf '302e020100300506032b657004220420'; printf '%s' "$seed"; } | xxd -r -p >"$tmp/$1.der"
    openssl pkey -inform DER -in "$tmp/$1.der" -out "$tmp/$1.pem" 2>/dev/null
    openssl pkey -in "$tmp/$1.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 >"$KEYS/$1.pub"
}
mkkey test1 "AIEN OSC UNIT ARTIFACT V1 THROWAWAY TEST KEY 1 (TEST ONLY, NOT A REAL KEY)"
mkkey owner1 "AIEN OSC UNIT ARTIFACT V1 THROWAWAY TEST KEY 2 (TEST ONLY, NOT A REAL KEY)"
fp() { hex2bin "$(cat "$KEYS/$1.pub")" | sha; }

# resign FILE KEY : recompute the signature over header+table, replace last 64 bytes
resign() {
    local f=$1 key=$2 n digest
    n=$(stat -c %s "$f")
    digest=$(head -c 320 "$f" | { printf 'AIENOS-OSC-UNIT-V1\0'; cat; } | sha)
    { printf 'AIENOS-OSC-UNIT-SIGNATURE-V1\0'; hex2bin "$digest"; } >"$tmp/msg"
    openssl pkeyutl -sign -inkey "$tmp/$key.pem" -rawin -in "$tmp/msg" -out "$tmp/sig" 2>/dev/null
    { head -c $((n - 64)) "$f"; cat "$tmp/sig"; } >"$f.new"
    mv "$f.new" "$f"
}

# ---- entry table (real functions of min.osc, from the compiler) -----------
namehash() { { printf 'AIENOS-OSC-FN-NAME-V1\0'; printf '%s' "$1"; } | sha | head -c 32; }
# entry FN_INDEX NREGS RET K0 K1 K2 K3 K4 K5 CODE_OFFSET NAME [HASH_HEX] [NAMELEN]
# 96-byte record: 32-byte fixed part (name_hash is an index only) then name_len u8 and name[63]
entry() {
    local name=${11} h=${12:-} nl=${13:-${#11}}
    [ -n "$h" ] || h=$(namehash "$name")
    le16 "$1"; u8 "$2"; u8 "$3"; u8 "$4"; u8 "$5"; u8 "$6"; u8 "$7"; u8 "$8"; u8 "$9"; le16 0
    le32 "${10}"; hex2bin "$h"
    u8 "$nl"; printf '%s' "$name"; zeros $((63 - ${#name}))
}
entries_min() { entry 0 2 5 5 5 0 0 0 0 0 add; entry 1 2 5 11 5 0 0 0 0 60 first_byte; }

# ---- caps section ---------------------------------------------------------
caps_none() { le16 0; zeros 6; }
# cap KIND ID RIGHTS BOUNDS_KIND MAXOPS MAXBYTES OFF LEN DOMAIN GENERATION
cap() {
    le16 "$1"; le16 0; le32 "$2"; le32 "$3"; le32 "$4"; le32 "$5"; le32 0
    le64 "$6"; le64 "$7"; le64 "$8"; le16 "$9"; le16 0; le32 0; le64 "${10}"
}

# ---- container builder ----------------------------------------------------
# build OUT KEYNAME CLASS UFV ABI NFN IRFILE CODEFILE ENTFILE CAPFILE
build() {
    local out=$1 key=$2 class=$3 ufv=$4 abi=$5 nfn=$6 irf=$7 codef=$8 entf=$9 capf=${10}
    local o1 o2 o3 o4 l1 l2 l3 l4 end total
    l1=$(stat -c %s "$irf"); l2=$(stat -c %s "$codef"); l3=$(stat -c %s "$entf"); l4=$(stat -c %s "$capf")
    o1=320; o2=$(align16 $((o1 + l1))); o3=$(align16 $((o2 + l2))); o4=$(align16 $((o3 + l3)))
    end=$((o4 + l4)); total=$((end + 64))
    {
        printf 'OSCUNIT\0'; le16 1; le16 128; le16 "$ufv"; le16 "$abi"; le32 0; le32 "$total"
        le32 128; le16 4; le16 48; le16 "$nfn"; le16 0
        le32 65536; le64 1000000; le16 0; le16 0; le32 0
        le16 "$class"; le16 1; le32 0; hex2bin "$(fp "$key")"; zeros 32
        local k=1 o l f
        for f in "$irf" "$codef" "$entf" "$capf"; do
            case $k in 1) o=$o1; l=$l1 ;; 2) o=$o2; l=$l2 ;; 3) o=$o3; l=$l3 ;; 4) o=$o4; l=$l4 ;; esac
            le16 $k; le16 0; le32 $o; le32 $l; le32 0; hex2bin "$(sha <"$f")"
            k=$((k + 1))
        done
        cat "$irf"; zeros $((o2 - o1 - l1))
        cat "$codef"; zeros $((o3 - o2 - l2))
        cat "$entf"; zeros $((o4 - o3 - l3))
        cat "$capf"
        zeros 64
    } >"$out"
    resign "$out" "$key"
}

cp "$SRC/min.ir" "$tmp/ir"; cp "$SRC/min.code" "$tmp/code"
entries_min >"$tmp/ent"; caps_none >"$tmp/caps0"
# one object READ request, kernel domain (1), generation 7
{ le16 1; zeros 6; cap 3 1 1 1 4 4096 0 4096 1 7; } >"$tmp/caps1"
# hosted-domain (2) request with a generation above 2^32
{ le16 1; zeros 6; cap 3 1 1 1 4 4096 0 4096 2 1099511627777; } >"$tmp/caps2"
# kernel-domain request whose generation does not fit 32 bits
{ le16 1; zeros 6; cap 3 1 1 1 4 4096 0 4096 1 4294967296; } >"$tmp/capsbig"

V=$OUT
build "$V/a01_valid_min.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent" "$tmp/caps0"
build "$V/a02_valid_caps_kernel_domain.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent" "$tmp/caps1"
build "$V/a03_valid_hosted_domain.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent" "$tmp/caps2"
build "$V/a04_valid_owner_class.unit" owner1 2 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent" "$tmp/caps0"
base=$V/a01_valid_min.unit
sz=$(stat -c %s "$base")

m() { # NAME OFFSET HEX... : patch base, then re-sign with test1
    local name=$1 off=$2
    shift 2
    patch "$base" "$off" "$@" >"$V/$name"
    resign "$V/$name" test1
}
m r01_bad_magic.unit 0 58
m r02_container_version_2.unit 8 02
m r03_unit_format_6.unit 12 06
m r04_abi_version_2.unit 14 02
m r05_unknown_flags.unit 16 01
m r06_header_field_reserved.unit 34 01
head -c $((sz - 100)) "$base" >"$V/r07_truncated_file.unit"
# section 2 (code) claims a length that runs past the signature
m r08_section_bounds.unit 184 ff ff 00 00
# section 2 (code) starts inside section 1 (IR)
m r09_section_overlap.unit 180 50 01 00 00
m r10_section_layout_offset.unit 180 b8 01 00 00
m r11_too_many_functions.unit 32 21 00
# content tampered, table untouched (signature still valid over the table)
patch "$base" 440 $(printf %02x $(($(xxd -p -s 440 -l 1 "$base" | head -c2 | sed 's/^/0x/' | xargs printf %d) ^ 1))) >"$V/r12_code_hash_mismatch.unit"
patch "$base" 330 $(printf %02x $(($(xxd -p -s 330 -l 1 "$base" | head -c2 | sed 's/^/0x/' | xargs printf %d) ^ 1))) >"$V/r13_ir_hash_mismatch.unit"
# last signature byte flipped
patch "$base" $((sz - 1)) $(printf %02x $(($(xxd -p -s $((sz - 1)) -l 1 "$base" | sed 's/^/0x/' | xargs printf %d) ^ 1))) >"$V/r14_bad_signature.unit"
# IR version byte (offset 327 = 320 + 7) disagrees with the header
{
    cp "$tmp/ir" "$tmp/ir_v4"
    patch "$tmp/ir" 7 04 >"$tmp/ir_v4"
    build "$V/r15_ir_version_mismatch.unit" test1 1 5 1 2 "$tmp/ir_v4" "$tmp/code" "$tmp/ent" "$tmp/caps0"
}
# entry table: function 1 claims an unaligned code offset (61)
{
    { entry 0 2 5 5 5 0 0 0 0 0 add; entry 1 2 5 11 5 0 0 0 0 61 first_byte; } >"$tmp/ent_bad"
    build "$V/r16_entry_table_unaligned.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_bad" "$tmp/caps0"
}
# 33 functions: a real 33-entry table, header count 33
{
    for i in $(seq 0 32); do entry "$i" 0 0 0 0 0 0 0 0 $((i * 4)) "f$i"; done >"$tmp/ent33"
    head -c 132 "$tmp/code" >"$tmp/code33"
    build "$V/r17_too_many_functions.unit" test1 1 5 1 33 "$tmp/ir" "$tmp/code33" "$tmp/ent33" "$tmp/caps0"
}
build "$V/r18_gen_not_representable.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent" "$tmp/capsbig"
# same bytes as a01; the verdict differs only by loader mode (see expected.txt)
cp "$base" "$V/r19_test_signer_release.unit"
cp "$V/a03_valid_hosted_domain.unit" "$V/r20_domain_unsupported.unit"
cp "$V/a04_valid_owner_class.unit" "$V/r21_untrusted_owner_signer.unit"
# unsigned trailing byte
{ cat "$base"; printf '\0'; } >"$V/r22_trailing_byte.unit"

# ---- entry name rules (bounded exact-match names; hash is only an index) ---
ent_with() { # NAME_OF_FILE ENTRY1_ARGS... : entry 0 (add) then a custom entry 1
    local out=$1; shift
    { entry 0 2 5 5 5 0 0 0 0 0 add; entry "$@"; } >"$out"
}
ent_with "$tmp/ent_charset" 1 2 5 11 5 0 0 0 0 60 "bad name"
ent_with "$tmp/ent_empty" 1 2 5 11 5 0 0 0 0 60 ""
ent_with "$tmp/ent_long" 1 2 5 11 5 0 0 0 0 60 first_byte "" 64
ent_with "$tmp/ent_dup" 1 2 5 11 5 0 0 0 0 60 add
ent_with "$tmp/ent_hashshare" 1 2 5 11 5 0 0 0 0 60 first_byte "$(namehash add)"
entries_min >"$tmp/ent_pad"
# nonzero byte in the padding after "add" (entry 0: name_len at 32, name at 33..35, padding from 36)
patch "$tmp/ent_pad" 38 41 >"$tmp/ent_pad2"
build "$V/r23_entry_name_charset.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_charset" "$tmp/caps0"
build "$V/r24_entry_name_empty.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_empty" "$tmp/caps0"
build "$V/r25_entry_name_too_long.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_long" "$tmp/caps0"
build "$V/r26_entry_name_padding.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_pad2" "$tmp/caps0"
build "$V/r27_entry_name_duplicate.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_dup" "$tmp/caps0"
build "$V/r28_entry_hash_shared_other_name.unit" test1 1 5 1 2 "$tmp/ir" "$tmp/code" "$tmp/ent_hashshare" "$tmp/caps0"

# ---- expected verdicts ----------------------------------------------------
# columns: vector mode domains anchors verdict
udig() { head -c 320 "$1" | { printf 'AIENOS-OSC-UNIT-V1\0'; cat; } | sha; }
irid=$(sha <"$SRC/min.ir")
{
    echo "# vector mode domains anchors verdict   (anchors: T TEST anchor present, O OWNER anchor present, - none)"
    echo "a01_valid_min.unit qualification 1 T ACCEPT unit_digest=$(udig "$V/a01_valid_min.unit") program_id=$irid"
    echo "a02_valid_caps_kernel_domain.unit qualification 1 T ACCEPT unit_digest=$(udig "$V/a02_valid_caps_kernel_domain.unit") program_id=$irid"
    echo "a03_valid_hosted_domain.unit qualification 1,2 T ACCEPT unit_digest=$(udig "$V/a03_valid_hosted_domain.unit") program_id=$irid"
    echo "a04_valid_owner_class.unit release 1 O ACCEPT unit_digest=$(udig "$V/a04_valid_owner_class.unit") program_id=$irid"
    echo "r01_bad_magic.unit qualification 1 T REFUSED BAD_MAGIC 2"
    echo "r02_container_version_2.unit qualification 1 T REFUSED CONTAINER_VERSION 3"
    echo "r03_unit_format_6.unit qualification 1 T REFUSED UNIT_FORMAT 5"
    echo "r04_abi_version_2.unit qualification 1 T REFUSED ABI_VERSION 6"
    echo "r05_unknown_flags.unit qualification 1 T REFUSED UNKNOWN_FLAGS 7"
    echo "r06_header_field_reserved.unit qualification 1 T REFUSED HEADER_FIELD 4"
    echo "r07_truncated_file.unit qualification 1 T REFUSED TRUNCATED 1"
    echo "r08_section_bounds.unit qualification 1 T REFUSED SECTION_BOUNDS 11"
    echo "r09_section_overlap.unit qualification 1 T REFUSED SECTION_OVERLAP 12"
    echo "r10_section_layout_offset.unit qualification 1 T REFUSED SECTION_LAYOUT 13"
    echo "r11_too_many_functions.unit qualification 1 T REFUSED LIMIT_EXCEEDED 14"
    echo "r12_code_hash_mismatch.unit qualification 1 T REFUSED CODE_HASH_MISMATCH 16"
    echo "r13_ir_hash_mismatch.unit qualification 1 T REFUSED IR_HASH_MISMATCH 15"
    echo "r14_bad_signature.unit qualification 1 T REFUSED BAD_SIGNATURE 26"
    echo "r15_ir_version_mismatch.unit qualification 1 T REFUSED IR_MALFORMED 19"
    echo "r16_entry_table_unaligned.unit qualification 1 T REFUSED ENTRY_TABLE 20"
    echo "r17_too_many_functions.unit qualification 1 T REFUSED LIMIT_EXCEEDED 14"
    echo "r18_gen_not_representable.unit qualification 1 T REFUSED CAP_GEN_NOT_REPRESENTABLE 28"
    echo "r19_test_signer_release.unit release 1 T REFUSED TEST_SIGNER_IN_RELEASE 24"
    echo "r20_domain_unsupported.unit qualification 1 T REFUSED CAP_DOMAIN_UNSUPPORTED 27"
    echo "r21_untrusted_owner_signer.unit release 1 - REFUSED UNTRUSTED_SIGNER 25"
    echo "r22_trailing_byte.unit qualification 1 T REFUSED TRAILING_BYTES 8"
    echo "r23_entry_name_charset.unit qualification 1 T REFUSED ENTRY_NAME 31"
    echo "r24_entry_name_empty.unit qualification 1 T REFUSED ENTRY_NAME 31"
    echo "r25_entry_name_too_long.unit qualification 1 T REFUSED ENTRY_NAME 31"
    echo "r26_entry_name_padding.unit qualification 1 T REFUSED ENTRY_NAME 31"
    echo "r27_entry_name_duplicate.unit qualification 1 T REFUSED ENTRY_NAME_DUPLICATE 33"
    echo "r28_entry_hash_shared_other_name.unit qualification 1 T REFUSED ENTRY_NAME_HASH 32"
} >"$V/expected.txt"

# ---- lookup-by-name expectations (exact match; hash is only an index) ------
{
    echo "# vector mode domains anchors name verdict"
    echo "a01_valid_min.unit qualification 1 T add ACCEPT fn_index=0"
    echo "a01_valid_min.unit qualification 1 T first_byte ACCEPT fn_index=1"
    echo "a01_valid_min.unit qualification 1 T ADD REFUSED LAUNCH_BAD_ENTRY 40"
    echo "a01_valid_min.unit qualification 1 T ad REFUSED LAUNCH_BAD_ENTRY 40"
    echo "a01_valid_min.unit qualification 1 T first_byt REFUSED LAUNCH_BAD_ENTRY 40"
    echo "a01_valid_min.unit qualification 1 T missing REFUSED LAUNCH_BAD_ENTRY 40"
} >"$V/lookups.txt"
