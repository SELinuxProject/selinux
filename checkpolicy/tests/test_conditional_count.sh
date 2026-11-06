#!/bin/sh
set -eu

BASEDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CHECKPOLICY=${CHECKPOLICY:-"${BASEDIR}/../checkpolicy"}
OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/conditional-count.XXXXXX")
trap 'rm -rf "$OUTDIR"' EXIT HUP INT TERM

for count in 1 4 5 6 8; do
    {
        printf '%s\n' 'class file' 'sid kernel' 'class file { read write }'
        i=1
        expr=b1
        while [ "$i" -le "$count" ]; do
            printf 'bool b%s false;\n' "$i"
            if [ "$i" -gt 1 ]; then
                expr="($expr || b$i)"
            fi
            i=$((i + 1))
        done
        printf '%s\n' 'type test_t;' 'allow test_t self:file read;'
        printf 'if (%s) { allow test_t self:file write; }\n' "$expr"
        printf '%s\n' 'role test_r;' 'role test_r types test_t;' \
            'user system_u roles test_r;' 'sid kernel system_u:test_r:test_t'
    } > "$OUTDIR/policy.conf"
    for optimize in '' '-O'; do
        # The optional flag is deliberately unquoted when empty.
        "$CHECKPOLICY" $optimize -o "$OUTDIR/policy.bin" "$OUTDIR/policy.conf"
        "$CHECKPOLICY" -b -F -o "$OUTDIR/roundtrip.conf" "$OUTDIR/policy.bin"
        "$CHECKPOLICY" $optimize -o "$OUTDIR/roundtrip.bin" "$OUTDIR/roundtrip.conf"
        cmp "$OUTDIR/policy.bin" "$OUTDIR/roundtrip.bin"
    done
done
printf '%s\n' 'conditional count: 10 compiler round trips passed'
