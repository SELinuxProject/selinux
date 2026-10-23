#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT HUP INT TERM
${CC:-cc} ${CFLAGS:--O1 -g -Wall -Wextra -Werror} \
    -DHAVE_REALLOCARRAY -fno-semantic-interposition \
    -ffunction-sections -fdata-sections -Ilibsemanage/include \
    -Ilibsemanage/src -Ilibsepol/include \
    libsemanage/tests/ibpkey-validation/test.c \
    libsemanage/src/ibpkeys_local.c libsemanage/src/ibpkey_record.c \
    libsepol/src/ibpkey_record.c libsepol/src/context_record.c \
    libsepol/src/debug.c ${LDFLAGS:-} -Wl,--gc-sections \
    -Wl,--wrap=malloc -Wl,--wrap=free -o "$out/test"
for scenario in empty single adjacent different overlap fail0 fail1 fail2 fail3 fail4; do
    "$out/test" "$scenario"
done
