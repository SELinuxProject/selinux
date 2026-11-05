#!/bin/sh
set -eu

CHECKPOLICY=${CHECKPOLICY:-./checkpolicy}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat > "$tmp/prefix" <<'EOF'
class file
sid kernel
class file { read write }
attribute excluded;
attribute domain;
type source_t, domain;
type excluded_t, excluded, domain;
type ordinary_t, domain;
typealias source_t alias source_alias_t;
EOF
cat > "$tmp/suffix" <<'EOF'
user user_u roles role_r;
sid kernel user_u:role_r:source_t
EOF

count=0
for side in source target positive; do
    case $side in
        source) rule='allow { domain -excluded } ordinary_t:file write;' ;;
        target) rule='allow source_t { domain -excluded }:file write;' ;;
        positive) rule='allow excluded self:file write;' ;;
    esac
    for variant in control enabled disabled last_enabled last_disabled repeated_type require_only optional_only; do
        cat "$tmp/prefix" > "$tmp/input.conf"
        printf '%s\n' "$rule" \
            'allow source_alias_t self:file read;' \
            'role role_r;' 'role role_r types domain;' >> "$tmp/input.conf"
        enabled='optional { require { class file { read }; } attribute excluded; }'
        disabled='optional { require { type missing_t; } attribute excluded; }'
        case $variant in
            control) ;;
            enabled) printf '%s\n' "$enabled" >> "$tmp/input.conf" ;;
            disabled) printf '%s\n' "$disabled" >> "$tmp/input.conf" ;;
            last_enabled) printf '%s\n' "$disabled" "$enabled" >> "$tmp/input.conf" ;;
            last_disabled) printf '%s\n' "$enabled" "$disabled" >> "$tmp/input.conf" ;;
            repeated_type)
                printf '%s\n' 'optional { require { type missing_t; } type excluded_t; }' >> "$tmp/input.conf" ;;
            require_only)
                printf '%s\n' 'optional { require { attribute excluded; } allow source_t self:file read; }' >> "$tmp/input.conf" ;;
            optional_only)
                printf '%s\n' \
                    'optional { require { type missing_t; } type absent_t; }' \
                    'optional { require { type absent_t; } allow ordinary_t self:file write; }' >> "$tmp/input.conf" ;;
        esac
        cat "$tmp/suffix" >> "$tmp/input.conf"
        "$CHECKPOLICY" -m -o "$tmp/policy.bin" "$tmp/input.conf"
        "$CHECKPOLICY" -b -F -o "$tmp/output.conf" "$tmp/policy.bin"
        # Full binary round-trip equality covers types, aliases, role membership,
        # and rules, including exclusions on either side of an allow rule.
        if [ "$variant" = control ]; then
            cp "$tmp/output.conf" "$tmp/expected.conf"
        else
            diff -u "$tmp/expected.conf" "$tmp/output.conf"
        fi
        count=$((count + 1))
    done
done

for decl in \
    'type excluded_t;' \
    'typealias source_t alias source_alias_t;' \
    'attribute source_t;' \
    'type excluded;'; do
    cat "$tmp/prefix" > "$tmp/input.conf"
    printf '%s\n' "$decl" 'allow source_t self:file read;' \
        'role role_r;' 'role role_r types domain;' >> "$tmp/input.conf"
    cat "$tmp/suffix" >> "$tmp/input.conf"
    if "$CHECKPOLICY" -o "$tmp/policy.bin" "$tmp/input.conf" 2> "$tmp/error"; then
        echo 'unexpected duplicate declaration acceptance' >&2
        exit 1
    fi
    count=$((count + 1))
done
printf 'PASS %s multiple-declaration compiler cases\n' "$count"
