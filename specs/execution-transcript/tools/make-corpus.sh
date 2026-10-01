#!/bin/bash
# make-corpus.sh: regenerate the TRN1 (execution transcript, wire schema 1)
# shared conformance corpus. Language-neutral spec: ../TRN1_TRANSCRIPT_SPEC.md.
#
# Usage: make-corpus.sh OUT_DIR      (normally specs/execution-transcript/vectors)
#
# Every vector is built byte by byte here from the spec tables, with digests
# from coreutils sha256sum. Nothing is produced by the C reference verifier,
# so the corpus and the verifier are two independent readings of the spec;
# tools/check-corpus.sh makes them agree.
#
# Groups (all listed in OUT_DIR/expected.txt, pairs in OUT_DIR/compare.txt):
#   gNNN.trn  golden transcripts (accepted)
#   pNNN.trn  edge positives (accepted)
#   fNNN.trn  forged replays: valid chain, different history (accepted alone,
#             DIVERGENCE when compared with their golden)
#   mNNN.trn  mutated transcripts (refused with a named code and event)
# Shell only: no Python, no tools beyond coreutils.
set -eu
export LC_ALL=C
OUT=${1:?OUT_DIR}
mkdir -p "$OUT"
rm -f "$OUT"/*.trn "$OUT"/expected.txt "$OUT"/compare.txt

# ---- hex helpers (all integers little-endian) ---------------------------
# le BYTES VALUE: VALUE as BYTES little-endian bytes, in hex
le() {
    local n=$1 v=$2 h out="" i
    if [ "$n" -lt 8 ]; then v=$((v & ((1 << (8 * n)) - 1))); fi
    h=$(printf "%0$((2 * n))x" "$v")
    for ((i = 2 * n - 2; i >= 0; i -= 2)); do out+=${h:i:2}; done
    printf '%s' "$out"
}
h8() { le 1 "$1"; }
h16() { le 2 "$1"; }
h32() { le 4 "$1"; }
h64() { le 8 "$1"; }
zeros() { local i out=""; for ((i = 0; i < $1; i++)); do out+=00; done; printf '%s' "$out"; }
# txt STRING: the bytes of STRING in hex
txt() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
# bin HEX: write raw bytes
bin() { local e; e=$(printf '%s' "$1" | sed 's/../\\x&/g'); printf '%b' "$e"; }
# sha HEX: SHA-256 of the bytes, in hex
sha() { bin "$1" | sha256sum | cut -c1-64; }
# dig STRING: a fixed 32-byte digest used as test data
dig() { printf '%s' "$1" | sha256sum | cut -c1-64; }
# flip HEX BYTE_OFFSET: HEX with the low bit of that byte inverted
flip() {
    local h=$1 o=$(($2 * 2)) b
    b=$(printf '%02x' $((0x${h:o:2} ^ 1)))
    printf '%s' "${h:0:o}$b${h:o+2}"
}

# ---- transcript builder ---------------------------------------------------
# A transcript is built in the shell variables T (hex so far), PREV (digest of
# the last record or header), SEQ, and OFF[i]/LEN[i] (byte offset and length
# of record i, 1-based), so byte-level mutants can find records.
SUB_TRANSCRIPT=0 SUB_WORLD=1 SUB_CORTEX=2 SUB_JSPACE=3 SUB_KERNEL=4 SUB_ARGUS=5
SUB_RUNTIME=7 SUB_SCHED=8 SUB_KV=9 SUB_EXTERNAL=10
# start PRODUCER RUN_ID_HEX [SCHEMA] [FLAGS] [RESERVED_HEX]
start() {
    T="TRN1"
    T=$(txt TRN1)$(h16 "${3:-1}")$(h16 "${4:-0}")$2$(h16 "$1")${5:-$(zeros 6)}
    PREV=$(sha "$T")
    SEQ=0
    OFF=() LEN=()
}
# rec TYPE SUB IDENT_HEX ANNOT_HEX [SEQ] [PREV] [RESERVED] [IDENT_LEN]
rec() {
    local s=${5:-$((SEQ + 1))} p=${6:-$PREV} il=${8:-$((${#3} / 2))} r
    r=$(h16 "$1")$(h16 "$2")$(h32 "$il")$(h32 $((${#4} / 2)))$(h32 "${7:-0}")$(h64 "$s")$p$3$4
    SEQ=$((SEQ + 1))
    OFF[SEQ]=$((${#T} / 2))
    LEN[SEQ]=$((${#r} / 2))
    T+=$r
    PREV=$(sha "$r")
}
end() { rec 65535 $SUB_TRANSCRIPT "$(h64 $((SEQ + 1)))$(zeros 8)" "${1:-}"; }
save() { bin "$T" >"$OUT/$1"; }

# ---- record identity builders (spec section 5) ------------------------------
sched() { printf '%s' "$(h64 "$1")$(h64 "$2")$(h64 "$3")$(h64 "$4")"; }
branch_create() { printf '%s' "$(h64 "$1")$(h64 "$2")$(h64 "$3")"; }
branch_destroy() { printf '%s' "$(h64 "$1")$(h64 "$2")$(h32 "$3")$(zeros 4)"; }
rng_seed() { printf '%s' "$(h64 "$1")$2"; }
rng_draw() { printf '%s' "$(h64 "$1")$(h64 "$2")$(h64 "$3")"; }
artifact() { printf '%s' "$(h32 "$1")$(zeros 4)$(h64 "$2")$3"; }
# cap_transition CAP OP GEN_BEFORE GEN_AFTER PRINCIPAL ISSUER [RESERVED3_HEX]
cap_transition() { printf '%s' "$(h32 "$1")$(h8 "$2")${7:-000000}$(h64 "$3")$(h64 "$4")$(h32 "$5")$(h32 "$6")"; }
cortex_read() { printf '%s' "$(h32 "$1")$(h32 "$2")$(h64 "$3")$(h64 "$4")$5"; }
effect_intent() { printf '%s' "$(h64 "$1")$(h32 "$2")$(h32 "$3")$(h64 "$4")$5"; }
effect_commit() { printf '%s' "$(h64 "$1")$(h32 "$2")$(zeros 4)$3"; }
# external_input SOURCE INPUT_SEQ CONTENT_HEX [DIGEST_HEX]
external_input() { printf '%s' "$(h32 "$1")$(zeros 4)$(h64 "$2")${4:-$(sha "$3")}$3"; }
clock_read() { printf '%s' "$(h32 "$1")$(zeros 4)$(h64 "$2")"; }
crash_boundary() { printf '%s' "$(h64 "$1")$(h64 "$2")$3"; }
checkpoint() { printf '%s' "$(h32 "$1")$(zeros 4)$2"; }
# Omega RxCrumb canonical bytes (rx_world.c crumb_hash, after the tag):
# crumb_canon ID KIND REACTION FACULTY WAKE COALESCED INPUTS_HEX CAPS_HEX OUTPUTS_HEX REASON PARENTS_HEX
# where INPUTS_HEX etc. already start with their u32 count.
crumb_canon() { printf '%s' "$(h64 "$1")$(h32 "$2")$(h32 "$3")$(h32 "$4")$(h64 "$5")$(h64 "$6")$7$8$9$(h32 "${10}")${11}"; }
objv() { printf '%s' "$(h32 "$1")$(h32 "$2")$(h64 "$3")$(h64 "$4")"; }   # obj id, obj gen, version, mask
capv() { printf '%s' "$(h32 "$1")$(h64 "$2")$(h32 "$3")"; }               # cap id, 64-bit generation, issuer
crumb_digest() { sha "$(txt AIEN_RX_CAUSAL_V1)$1"; }
# rx_crumb CANON [DIGEST]: RX_CRUMB identity = digest || canonical bytes
rx_crumb() { printf '%s' "${2:-$(crumb_digest "$1")}$1"; }
crumb_annot() { printf '%s' "$(h32 "$1")$(h64 "$2")$(h64 "$3")$(h64 "$4")"; }  # worker, t_start, t_end, episode
# ARGUS: 128-byte ArgusEvent wire bytes (aienos native/argus/argus_event.c encode_raw)
# argus_ev SEQUENCE KIND CLASS OUTCOME PRINCIPAL CAP_ID CAP_GEN
argus_ev() {
    printf '%s' "$(h8 1)$(h8 "$3")$(h16 "$2")$(h8 0)$(h8 "$4")$(h16 0)$(h64 "$1")$(h64 "$1")$(h32 "$5")$(h32 0)$(h32 "$6")$(h32 0)$(h64 "$7")$(h64 1)$(h64 0)$(dig "machine A1")$(dig "evidence $1")"
}
# argus_rec EVENT_HEX CHAINED BEFORE_HEX [AFTER_HEX] [RESERVED7_HEX]
argus_rec() {
    local after=${4:-}
    if [ -z "$after" ]; then
        if [ "$2" != 0 ]; then after=$(sha "$3$1"); else after=$3; fi
    fi
    printf '%s' "$1$(h8 "$2")${5:-$(zeros 7)}$3$after"
}
ARGUS_AFTER=""
sched_annot() { printf '%s' "$(h32 "$1")$(h64 "$2")"; }   # worker, wall time (not compared)

# ---- manifests ------------------------------------------------------------
{
    echo "# TRN1 shared conformance corpus. Spec: TRN1_TRANSCRIPT_SPEC.md (contract 0.1.0, wire schema 1)."
    echo "# Line: <file> ok records=N run=<64 hex> final=<64 hex>"
    echo "#   or: <file> refuse <code> event=<record position, 0 = file header>"
    echo "#   codes: -1 MAGIC -2 VERSION -3 LENGTH -4 NONCANONICAL -5 UNKNOWN -6 SHAPE"
    echo "#          -7 GAP -8 CHAIN -9 DIGEST -10 TRUNCATED"
    echo "# Generated by tools/make-corpus.sh; do not edit by hand."
} >"$OUT/expected.txt"
{
    echo "# TRN1 replay comparison pairs. Spec section 8."
    echo "# Line: <expected file> <actual file> MATCH through N"
    echo "#   or: <expected file> <actual file> DIVERGENCE event=N expected=<64 hex> actual=<64 hex> subsystem=<name>"
    echo "#   or: <expected file> <actual file> refuse expected|actual <code> event=N"
    echo "# Generated by tools/make-corpus.sh; do not edit by hand."
} >"$OUT/compare.txt"
ok() { echo "$1 ok records=$2 run=$3 final=$PREV" >>"$OUT/expected.txt"; }
refuse() { echo "$1 refuse $2 event=$3" >>"$OUT/expected.txt"; }
pair() { echo "$1 $2 $3" >>"$OUT/compare.txt"; }
# Compared digest of record I of the transcript in T (spec section 8).
cmpd() {
    local i=$1 o=$((OFF[$1] * 2)) il
    il=$((0x$(printf '%s' "${T:o+14:2}${T:o+12:2}${T:o+10:2}${T:o+8:2}")))
    sha "$(txt AIEN_TRN1_CMP)${T:o:8}${T:o+32:16}${T:o+8:8}${T:o+112:il*2}"
}
# cut FILE_HEX START_BYTE COUNT: bytes [START, START+COUNT)
cut_hex() { printf '%s' "${1:$(($2 * 2)):$(($3 * 2))}"; }

# ===========================================================================
# g001: Omega World run (producer omega-world). Every record kind a World
# writes today, including two real RxCrumbs (create, then commit with parent).
# ===========================================================================
RUN1=$(dig "run g001")
C1=$(crumb_canon 1 1 4294967295 0 0 0 "$(h32 0)" "$(h32 0)" "$(h32 1)$(objv 5 1 3 255)" 0 "$(h32 0)")
C1D=$(crumb_digest "$C1")
C2=$(crumb_canon 2 3 3 1 1 0 "$(h32 1)$(objv 5 1 3 255)" "$(h32 1)$(capv 4 9 1)" "$(h32 1)$(objv 6 1 1 1)" 0 "$(h32 1)$(h64 1)$C1D")
g001() { # g001 [worker-time skew for replay annotations] [run id]
    local w=${1:-0}
    start $SUB_WORLD "${2:-$RUN1}"
    rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001")")" ""
    rec 2 $SUB_JSPACE "$(branch_create 7 0 1)" ""
    rec 1 $SUB_WORLD "$(sched 1 3 0 0)" "$(sched_annot $((2 + w)) $((1000 + w * 77)))"
    rec 8 $SUB_CORTEX "$(cortex_read 5 1 3 255 "$(dig "cortex obj5 v3")")" ""
    rec 15 $SUB_WORLD "$(rx_crumb "$C1")" "$(crumb_annot $((1 + w)) $((2000 + w)) $((2100 + w)) 1)"
    rec 15 $SUB_WORLD "$(rx_crumb "$C2")" "$(crumb_annot $((2 + w)) $((2200 + w)) $((2900 + w)) 1)"
    rec 7 $SUB_KERNEL "$(cap_transition 4 2 9 10 3 1)" ""
    rec 9 $SUB_WORLD "$(effect_intent 1 2 4 10 "$(dig "effect 1 request")")" ""
    rec 10 $SUB_WORLD "$(effect_commit 1 0 "$(dig "effect 1 result")")" ""
    rec 14 $SUB_WORLD "$(checkpoint 1 "$(dig "world state after g001")")" ""
}
g001; end; save g001.trn; ok g001.trn 11 "$RUN1"
G1=$T
G1CMP=(); for i in $(seq 1 11); do G1CMP[i]=$(cmpd "$i"); done

# g005: replay of g001 on another schedule. Different run id, workers and
# wall times (annotations); same identities. Verifies alone and MATCHes g001.
RUN5=$(dig "run g005 replay of g001")
g001 3 "$RUN5"; end; save g005.trn; ok g005.trn 11 "$RUN5"
pair g001.trn g005.trn "MATCH through 11"
pair g001.trn g001.trn "MATCH through 11"

# ===========================================================================
# g002: AIENOS ARGUS stream (producer aienos-argus). Two chained events, one
# malformed event recorded but not chained (argus_core step 0), a revoke.
# ===========================================================================
RUN2=$(dig "run g002")
E1=$(argus_ev 1 10 2 1 3 4 9)
E2=$(argus_ev 2 11 2 1 3 4 10)
E3=$(argus_ev 3 12 2 9 3 4 10)
Z32=$(zeros 32)
A1=$(sha "$Z32$E1"); A2=$(sha "$A1$E2")
start $SUB_ARGUS "$RUN2"
rec 16 $SUB_ARGUS "$(argus_rec "$E1" 1 "$Z32")" ""
rec 16 $SUB_ARGUS "$(argus_rec "$E2" 1 "$A1")" ""
rec 16 $SUB_ARGUS "$(argus_rec "$E3" 0 "$A2")" ""
rec 7 $SUB_KERNEL "$(cap_transition 4 4 10 11 3 1)" ""
rec 14 $SUB_ARGUS "$(checkpoint 2 "$A2")" ""
end; save g002.trn; ok g002.trn 6 "$RUN2"
G2=$T
pair g002.trn g002.trn "MATCH through 6"

# ===========================================================================
# g003: the remaining record types (producer sovcore-runtime), including a
# recovered crash boundary and external input with and without content.
# ===========================================================================
RUN3=$(dig "run g003")
IN1=$(txt "hello transcript")
g003() {
    start $SUB_RUNTIME "$RUN3"
    rec 11 $SUB_EXTERNAL "$(external_input 1 1 "$IN1")" ""
    rec 11 $SUB_EXTERNAL "$(external_input 1 2 "" "$(dig "input 2 stored elsewhere")")" ""
    rec 12 $SUB_RUNTIME "$(clock_read 1 42)" ""
    rec 5 $SUB_RUNTIME "$(rng_draw 1 0 12345)" ""
    rec 6 $SUB_RUNTIME "$(artifact 1 9 "$(dig "artifact 9")")" ""
    rec 2 $SUB_KV "$(branch_create 2 1 1)" ""
    rec 3 $SUB_KV "$(branch_destroy 2 1 -1)" ""
    rec 13 $SUB_RUNTIME "$(crash_boundary 2 7 "$(dig "recovered state epoch 2")")" ""
    rec 1 $SUB_SCHED "$(sched 1 1 0 0)" "$(sched_annot 0 5)"
    rec 14 $SUB_KV "$(checkpoint 3 "$(dig "kv pages after g003")")" ""
}
g003; end; save g003.trn; ok g003.trn 11 "$RUN3"
G3=$T

# g004: the smallest transcript, END only.
RUN4=$(dig "run g004")
start $SUB_KERNEL "$RUN4"; end; save g004.trn; ok g004.trn 1 "$RUN4"

# ===========================================================================
# Edge positives.
# ===========================================================================
# p001: largest external input content (4096 bytes) and a large annotation.
BIG=$(for i in $(seq 1 256); do printf '%s' "000102030405060708090a0b0c0d0e0f"; done)
start $SUB_RUNTIME "$(dig "run p001")"
rec 11 $SUB_EXTERNAL "$(external_input 2 1 "$BIG")" "$BIG$BIG"
end; save p001.trn; ok p001.trn 2 "$(dig "run p001")"
# p002: crumb at Omega's limits: 8 inputs, 8 caps, 8 outputs, and parents that
# carry no digest (p = 0 and p >= id), as crumb_hash writes them.
INS=$(h32 8); CAPS=$(h32 8); OUTS=$(h32 8)
for i in 1 2 3 4 5 6 7 8; do INS+=$(objv "$i" 1 "$i" 255); CAPS+=$(capv "$i" $((1 << 40)) 0); OUTS+=$(objv $((i + 8)) 2 1 1); done
CP=$(crumb_canon 5 3 2 1 4 2 "$INS" "$CAPS" "$OUTS" -3 "$(h32 4)$(h64 0)$(h64 4)$C1D$(h64 5)$(h64 9)")
start $SUB_WORLD "$(dig "run p002")"
rec 15 $SUB_WORLD "$(rx_crumb "$CP")" "$(crumb_annot 0 0 0 0)"
end; save p002.trn; ok p002.trn 2 "$(dig "run p002")"

# ===========================================================================
# Forged replays: each has a valid chain (accepted alone) but a different
# history than g001. Only comparison against the expected run finds them.
# ===========================================================================
div() { # div FILE EVENT SUBSYSTEM: record the DIVERGENCE pair against g001
    pair g001.trn "$1" "DIVERGENCE event=$2 expected=${G1CMP[$2]} actual=$(cmpd "$2") subsystem=$3"
}
# f001 omission: record 3 (scheduler decision) dropped, renumbered, rechained.
start $SUB_WORLD "$RUN1"
rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001")")" ""
rec 2 $SUB_JSPACE "$(branch_create 7 0 1)" ""
rec 8 $SUB_CORTEX "$(cortex_read 5 1 3 255 "$(dig "cortex obj5 v3")")" ""
rec 15 $SUB_WORLD "$(rx_crumb "$C1")" "$(crumb_annot 1 2000 2100 1)"
rec 15 $SUB_WORLD "$(rx_crumb "$C2")" "$(crumb_annot 2 2200 2900 1)"
rec 7 $SUB_KERNEL "$(cap_transition 4 2 9 10 3 1)" ""
rec 9 $SUB_WORLD "$(effect_intent 1 2 4 10 "$(dig "effect 1 request")")" ""
rec 10 $SUB_WORLD "$(effect_commit 1 0 "$(dig "effect 1 result")")" ""
rec 14 $SUB_WORLD "$(checkpoint 1 "$(dig "world state after g001")")" ""
end; save f001.trn; ok f001.trn 10 "$RUN1"; div f001.trn 3 omega-world
# f002 reorder: records 3 and 4 swapped, rechained.
start $SUB_WORLD "$RUN1"
rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001")")" ""
rec 2 $SUB_JSPACE "$(branch_create 7 0 1)" ""
rec 8 $SUB_CORTEX "$(cortex_read 5 1 3 255 "$(dig "cortex obj5 v3")")" ""
rec 1 $SUB_WORLD "$(sched 1 3 0 0)" "$(sched_annot 2 1000)"
rec 15 $SUB_WORLD "$(rx_crumb "$C1")" "$(crumb_annot 1 2000 2100 1)"
rec 15 $SUB_WORLD "$(rx_crumb "$C2")" "$(crumb_annot 2 2200 2900 1)"
rec 7 $SUB_KERNEL "$(cap_transition 4 2 9 10 3 1)" ""
rec 9 $SUB_WORLD "$(effect_intent 1 2 4 10 "$(dig "effect 1 request")")" ""
rec 10 $SUB_WORLD "$(effect_commit 1 0 "$(dig "effect 1 result")")" ""
rec 14 $SUB_WORLD "$(checkpoint 1 "$(dig "world state after g001")")" ""
end; save f002.trn; ok f002.trn 11 "$RUN1"; div f002.trn 3 omega-world
# f003: different RNG seed (first record).
start $SUB_WORLD "$RUN1"
rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001 other")")" ""
end; save f003.trn; ok f003.trn 2 "$RUN1"; div f003.trn 1 omega-world
# f004: crumb 2 used capability generation 8 instead of 9 (digest recomputed).
C2X=$(crumb_canon 2 3 3 1 1 0 "$(h32 1)$(objv 5 1 3 255)" "$(h32 1)$(capv 4 8 1)" "$(h32 1)$(objv 6 1 1 1)" 0 "$(h32 1)$(h64 1)$C1D")
start $SUB_WORLD "$RUN1"
rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001")")" ""
rec 2 $SUB_JSPACE "$(branch_create 7 0 1)" ""
rec 1 $SUB_WORLD "$(sched 1 3 0 0)" "$(sched_annot 2 1000)"
rec 8 $SUB_CORTEX "$(cortex_read 5 1 3 255 "$(dig "cortex obj5 v3")")" ""
rec 15 $SUB_WORLD "$(rx_crumb "$C1")" "$(crumb_annot 1 2000 2100 1)"
rec 15 $SUB_WORLD "$(rx_crumb "$C2X")" "$(crumb_annot 2 2200 2900 1)"
end; save f004.trn; ok f004.trn 7 "$RUN1"; div f004.trn 6 omega-world
# f005: one extra clock read before END.
g001; rec 12 $SUB_WORLD "$(clock_read 1 99)" ""; end; save f005.trn; ok f005.trn 12 "$RUN1"; div f005.trn 11 transcript
# f006: run stopped early (END after record 5).
start $SUB_WORLD "$RUN1"
rec 4 $SUB_WORLD "$(rng_seed 1 "$(dig "seed g001")")" ""
rec 2 $SUB_JSPACE "$(branch_create 7 0 1)" ""
rec 1 $SUB_WORLD "$(sched 1 3 0 0)" "$(sched_annot 2 1000)"
rec 8 $SUB_CORTEX "$(cortex_read 5 1 3 255 "$(dig "cortex obj5 v3")")" ""
rec 15 $SUB_WORLD "$(rx_crumb "$C1")" "$(crumb_annot 1 2000 2100 1)"
end; save f006.trn; ok f006.trn 6 "$RUN1"; div f006.trn 6 omega-world

# ===========================================================================
# Byte-level mutants of g001 (damage after writing: nothing rechained).
# ===========================================================================
g001 >/dev/null; end   # refresh OFF/LEN for g001
mb() { bin "$1" >"$OUT/$2"; }
R() { printf '%s' "${OFF[$1]}"; }
# m001 omission: record 3 removed.
mb "${G1:0:$(($(R 3) * 2))}${G1:$(($(R 4) * 2))}" m001.trn; refuse m001.trn -7 3
# m002 reorder: records 3 and 4 swapped.
mb "${G1:0:$(($(R 3) * 2))}$(cut_hex "$G1" "$(R 4)" "${LEN[4]}")$(cut_hex "$G1" "$(R 3)" "${LEN[3]}")${G1:$(($(R 5) * 2))}" m002.trn; refuse m002.trn -7 3
# m003 bit flip in record 4 identity (cortex read digest): next record's prev breaks.
mb "$(flip "$G1" $(($(R 4) + 56 + 30)))" m003.trn; refuse m003.trn -8 5
# m004 bit flip in record 3 annotation (worker id): annotations are chained too.
mb "$(flip "$G1" $(($(R 3) + 56 + 32)))" m004.trn; refuse m004.trn -8 4
# m005 bit flip in record 2 prev field.
mb "$(flip "$G1" $(($(R 2) + 24 + 5)))" m005.trn; refuse m005.trn -8 2
# m006 bit flip in record 6 seq.
mb "$(flip "$G1" $(($(R 6) + 16)))" m006.trn; refuse m006.trn -7 6
# m007 bit flip in header run id.
mb "$(flip "$G1" 9)" m007.trn; refuse m007.trn -8 1
# m008 bit flip in magic.
mb "$(flip "$G1" 0)" m008.trn; refuse m008.trn -1 0
# m009 truncation inside record 5.
mb "${G1:0:$((($(R 5) + 70) * 2))}" m009.trn; refuse m009.trn -3 5
# m010 truncation at a record boundary: END lost.
mb "${G1:0:$(($(R 11) * 2))}" m010.trn; refuse m010.trn -10 11
# m011 truncation inside the file header.
mb "${G1:0:40}" m011.trn; refuse m011.trn -3 0
# m012 empty file.
: >"$OUT/m012.trn"; refuse m012.trn -3 0
# m013 truncation inside END.
mb "${G1:0:$((${#G1} - 6))}" m013.trn; refuse m013.trn -3 11
# m014 trailing byte after END.
mb "${G1}00" m014.trn; refuse m014.trn -3 12
# m015 duplicate: record 3 written twice.
mb "${G1:0:$(($(R 4) * 2))}$(cut_hex "$G1" "$(R 3)" "${LEN[3]}")${G1:$(($(R 4) * 2))}" m015.trn; refuse m015.trn -7 4
# m016 bit flip inside crumb 1 canonical bytes (record 5): its own crumb digest no longer matches.
mb "$(flip "$G1" $(($(R 5) + 56 + 32 + 12)))" m016.trn; refuse m016.trn -9 5
# m017 bit flip in END prev.
mb "$(flip "$G1" $(($(R 11) + 24)))" m017.trn; refuse m017.trn -8 11
# m018 bit flip in END record count.
mb "$(flip "$G1" $(($(R 11) + 56)))" m018.trn; refuse m018.trn -7 11

# ===========================================================================
# Built mutants: rechained, so only the named check can catch them.
# ===========================================================================
H() { start "${1:-$SUB_WORLD}" "$(dig "run $2")" "${3:-1}" "${4:-0}" "${5:-}"; }
# Header checks.
H $SUB_WORLD m020 2; end; save m020.trn; refuse m020.trn -2 0            # unknown future schema
H $SUB_WORLD m021 0; end; save m021.trn; refuse m021.trn -2 0            # schema 0
H $SUB_WORLD m022 1 1; end; save m022.trn; refuse m022.trn -4 0          # header flags set
H 0 m023; end; save m023.trn; refuse m023.trn -5 0                       # producer 0
H 11 m024; end; save m024.trn; refuse m024.trn -5 0                      # producer unknown
H $SUB_WORLD m025 1 0 "000000000100"; end; save m025.trn; refuse m025.trn -4 0   # header reserved
# Record header checks.
H $SUB_WORLD m030; rec 17 $SUB_WORLD "$(clock_read 1 1)" ""; end; save m030.trn; refuse m030.trn -5 1   # unknown type
H $SUB_WORLD m031; rec 12 11 "$(clock_read 1 1)" ""; end; save m031.trn; refuse m031.trn -5 1          # unknown subsystem
H $SUB_WORLD m032; rec 12 $SUB_WORLD "$(clock_read 1 1)" "" "" "" 1; end; save m032.trn; refuse m032.trn -4 1  # record reserved
H $SUB_WORLD m033; rec 12 $SUB_WORLD "$(clock_read 1 1)" "" 2; end; save m033.trn; refuse m033.trn -7 1  # seq skips (omission at start)
H $SUB_WORLD m034; rec 12 $SUB_WORLD "$(clock_read 1 1)" "" "" "$(dig other)"; end; save m034.trn; refuse m034.trn -8 1  # wrong prev
# Check order: unknown type wins over a bad seq.
H $SUB_WORLD m035; rec 17 $SUB_WORLD "$(clock_read 1 1)" "" 9; end; save m035.trn; refuse m035.trn -5 1
# Check order: a bad seq wins over a bad prev.
H $SUB_WORLD m036; rec 12 $SUB_WORLD "$(clock_read 1 1)" "" 9 "$(dig other)"; end; save m036.trn; refuse m036.trn -7 1
# Identity longer than the limit, fully present: LENGTH, not SHAPE.
HUGE=$(head -c 65537 /dev/zero | od -An -v -tx1 | tr -d ' \n')
H $SUB_WORLD m037; rec 1 $SUB_WORLD "$HUGE" ""; end; save m037.trn; refuse m037.trn -3 1
# Shape checks.
H $SUB_WORLD m040; rec 1 $SUB_WORLD "$(sched 1 3 0 0 | cut -c1-62)" ""; end; save m040.trn; refuse m040.trn -6 1   # SCHED 31 bytes
H $SUB_WORLD m041; rec 65535 $SUB_WORLD "$(h64 1)$(zeros 8)" ""; save m041.trn; refuse m041.trn -6 1                # END not subsystem 0
H $SUB_WORLD m042; rec 12 $SUB_TRANSCRIPT "$(clock_read 1 1)" ""; end; save m042.trn; refuse m042.trn -6 1          # subsystem 0 off END
H $SUB_WORLD m043; rec 7 $SUB_KERNEL "$(cap_transition 4 7 9 10 3 1)" ""; end; save m043.trn; refuse m043.trn -6 1  # cap op 7
H $SUB_WORLD m044; rec 13 $SUB_RUNTIME "$(crash_boundary 2 1 "$(dig x)")" ""; end; save m044.trn; refuse m044.trn -6 1  # last durable >= own seq
H $SUB_WORLD m045; rec 11 $SUB_EXTERNAL "$(external_input 1 1 "$BIG"00)" ""; end; save m045.trn; refuse m045.trn -6 1  # content 4097
H $SUB_WORLD m046; rec 15 $SUB_WORLD "$(dig short | cut -c1-40)" ""; end; save m046.trn; refuse m046.trn -6 1  # crumb identity < 32 bytes
CB9=$(crumb_canon 3 3 1 1 0 0 "$(h32 9)$(for i in 1 2 3 4 5 6 7 8 9; do objv "$i" 1 1 1; done)" "$(h32 0)" "$(h32 0)" 0 "$(h32 0)")
H $SUB_WORLD m047; rec 15 $SUB_WORLD "$(rx_crumb "$CB9")" ""; end; save m047.trn; refuse m047.trn -6 1  # 9 inputs (digest valid)
CBP=$(crumb_canon 3 3 1 1 0 0 "$(h32 0)" "$(h32 0)" "$(h32 0)" 0 "$(h32 1)$(h64 1)")
H $SUB_WORLD m048; rec 15 $SUB_WORLD "$(rx_crumb "$CBP")" ""; end; save m048.trn; refuse m048.trn -6 1  # parent 1 < id 3 without its digest
H $SUB_ARGUS m049; rec 16 $SUB_ARGUS "$(argus_rec "$E1" 2 "$Z32" "$(sha "$Z32$E1")")" ""; end; save m049.trn; refuse m049.trn -6 1  # chained flag 2
H $SUB_WORLD m050; end "00"; save m050.trn; refuse m050.trn -6 1                                                  # END with annotation
# Reserved fields inside identities.
H $SUB_WORLD m055; rec 7 $SUB_KERNEL "$(cap_transition 4 2 9 10 3 1 000100)" ""; end; save m055.trn; refuse m055.trn -4 1
H $SUB_WORLD m056; rec 65535 $SUB_TRANSCRIPT "$(h64 1)$(h64 1)" ""; save m056.trn; refuse m056.trn -4 1
H $SUB_ARGUS m057; rec 16 $SUB_ARGUS "$(argus_rec "$E1" 1 "$Z32" "" 00000000000001)" ""; end; save m057.trn; refuse m057.trn -4 1
# END count.
H $SUB_WORLD m058; rec 12 $SUB_WORLD "$(clock_read 1 1)" ""; rec 65535 $SUB_TRANSCRIPT "$(h64 5)$(zeros 8)" ""; save m058.trn; refuse m058.trn -7 2
# Embedded digests.
CBAD=$(crumb_canon 1 1 4294967295 0 0 0 "$(h32 0)" "$(h32 0)" "$(h32 1)$(objv 5 1 3 254)" 0 "$(h32 0)")
H $SUB_WORLD m060; rec 15 $SUB_WORLD "$(rx_crumb "$CBAD" "$C1D")" ""; end; save m060.trn; refuse m060.trn -9 1   # crumb digest stale
H $SUB_WORLD m061; rec 11 $SUB_EXTERNAL "$(external_input 1 1 "$(txt "hello transcripT")" "$(sha "$IN1")")" ""; end; save m061.trn; refuse m061.trn -9 1  # input content altered
H $SUB_ARGUS m062; rec 16 $SUB_ARGUS "$(argus_rec "$E1" 1 "$Z32" "$(dig wrong)")" ""; end; save m062.trn; refuse m062.trn -9 1  # chain_after wrong
H $SUB_ARGUS m063; rec 16 $SUB_ARGUS "$(argus_rec "$E1" 1 "$Z32")" ""; rec 16 $SUB_ARGUS "$(argus_rec "$E2" 1 "$Z32")" ""; end; save m063.trn; refuse m063.trn -9 2  # ARGUS event dropped between records 1 and 2
H $SUB_ARGUS m064; rec 16 $SUB_ARGUS "$(argus_rec "$E3" 0 "$Z32" "$A1")" ""; end; save m064.trn; refuse m064.trn -9 1  # unchained event moved the chain
# ARGUS stream with an event omitted, then rechained by the writer: the ARGUS
# continuity check still catches it (g002 without record 2).
start $SUB_ARGUS "$RUN2"
rec 16 $SUB_ARGUS "$(argus_rec "$E1" 1 "$Z32")" ""
rec 16 $SUB_ARGUS "$(argus_rec "$E3" 0 "$A2")" ""
end; save m065.trn; refuse m065.trn -9 2

# Compare against refused files.
pair g001.trn m001.trn "refuse actual -7 event=3"
pair m008.trn g001.trn "refuse expected -1 event=0"

echo "corpus written to $OUT: $(ls "$OUT"/*.trn | wc -l) transcripts"
