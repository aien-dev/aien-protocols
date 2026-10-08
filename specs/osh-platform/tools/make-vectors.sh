#!/bin/bash
# make-vectors.sh: regenerate the OSH conformance inputs (vNNN.in, vNNN.env).
# Format: ../vectors/README.md. expected.txt is committed by hand and is NOT
# written here. Shell only: no Python, coreutils only.
# Usage: make-vectors.sh OUT_DIR   (normally specs/osh-platform/vectors)
set -eu
export LC_ALL=C
OUT=${1:?OUT_DIR}
mkdir -p "$OUT"
rm -f "$OUT"/v*.in "$OUT"/v*.env
mkin()  { printf '%b' "$2" > "$OUT/$1.in"; }
mkenv() { printf '%b' "$2" > "$OUT/$1.env"; }
mkin v001 'ls -l /tmp\n'
mkin v002 'a && b || c; d | e\n'
mkin v003 'echo $? $# "$@"\n'; mkenv v003 '@status=3\n@arg1=x\n@arg2=y z\n'
mkin v004 'x=1 y="2 3"\n'
mkin v005 'echo "a${B}c" $1\n'; mkenv v005 'B=Q\n@arg1=hello\n'
mkin v006 'ls nofile >o 2>&1\n'
mkin v007 'echo *.c\n'
mkin v008 'echo $(x)\n'
mkin v009 'echo "unterminated\n'
mkin v010 'a & b\n'
mkin v011 'echo $X "$X" '"''"'\n'; mkenv v011 'X= a  b \n'
mkin v012 'echo $G\n'; mkenv v012 'G=*.c\n'
mkin v013 'echo a\0b\n'
mkin v014 'echo a\\\nb\n'
{ printf 'echo '; head -c 1100 /dev/zero | tr '\0' a; printf '\n'; } > "$OUT/v015.in"
