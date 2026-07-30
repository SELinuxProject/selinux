#!/bin/sh
#
# Negative / bad-data tests for checkmodule on module (.te) inputs.
# Matches the modular policy compile path: checkmodule -M -m <input> -o <module>.mod
#

set -eu

# Prefer an absolute script dir, but keep a relative dirname when cd fails.
# Non-root CI inherits the repo as CWD; absolute cd under /home/runner/work
# can fail for bad-data-test even when relative paths work.
BASEDIR=$(dirname -- "$0")
ABS_BASEDIR=$(CDPATH= cd -- "${BASEDIR}" 2>/dev/null && pwd) || ABS_BASEDIR=
if [ -n "${ABS_BASEDIR}" ]; then
	BASEDIR="${ABS_BASEDIR}"
fi
NEGDIR="${BASEDIR}/negative"
if [ ! -d "${NEGDIR}" ]; then
	echo "FAIL: cannot resolve negative fixtures (\$0=$0 BASEDIR=${BASEDIR})" >&2
	exit 1
fi
CHECKMODULE="${BASEDIR}/../checkmodule"
OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/checkmodule-negative.XXXXXX")
PASS=0
FAIL=0

cleanup() {
	rm -rf "${OUTDIR}"
}
trap cleanup EXIT

mod_name_from_fixture() {
	basename "$1" .te
}

expect_pass() {
	desc="$1"
	fixture="$2"
	modname=$(mod_name_from_fixture "${fixture}")
	outmod="${OUTDIR}/${modname}.mod"
	stderr="${OUTDIR}/${modname}.err"

	echo "==== POSITIVE (expect checkmodule success): ${desc}"
	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m -o "${outmod}" "${NEGDIR}/${fixture}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: expected success (rc=0), got rc=${rc}" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi
	if [ ! -s "${outmod}" ]; then
		echo "FAIL: expected non-empty ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi

	echo "==== ${desc} success"
	PASS=$((PASS + 1))
	echo ""
}

expect_fail() {
	desc="$1"
	pattern="$2"
	outname="${3:-fail}"
	shift 3

	outmod="${OUTDIR}/${outname}.mod"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== NEGATIVE (expect checkmodule error): ${desc}"
	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m "$@" -o "${outmod}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		echo "FAIL: expected non-zero exit, got rc=0" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi
	if [ -f "${outmod}" ]; then
		echo "FAIL: did not expect output module ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi
	if ! grep -Eq "${pattern}" "${stderr}"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi

	echo "==== ${desc}: rejected as expected"
	PASS=$((PASS + 1))
	echo ""
}

expect_fail_unreadable() {
	desc="unreadable .te file"
	fixture="${OUTDIR}/unreadable.te"
	outmod="${OUTDIR}/unreadable.mod"
	stderr="${OUTDIR}/unreadable.err"

	echo "==== NEGATIVE (expect checkmodule error): ${desc}"
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIP: root can read mode 000 files; unreadable check is non-root only"
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m -o "${outmod}" "${fixture}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		echo "FAIL: expected non-zero exit, got rc=0" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi
	if [ -f "${outmod}" ]; then
		echo "FAIL: did not expect output module ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi
	if ! grep -Eq 'unable to open|Permission denied' "${stderr}"; then
		echo "FAIL: stderr did not mention unable to open or Permission denied" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 1
	fi

	echo "==== ${desc}: rejected as expected"
	PASS=$((PASS + 1))
	echo ""
}

# Ephemeral fixtures for path-based cases.
ln -sf /nonexistent/path "${OUTDIR}/broken_symlink.te"
cat > "${OUTDIR}/unreadable.te" <<'EOF'
module unreadable 1.0;

require {
	type foo_t;
}
EOF
chmod 000 "${OUTDIR}/unreadable.te"

# Control fixture: valid module compiles and produces .mod output.
expect_pass "good_module.te" "good_module.te"

# Corrupted .te sections (PDF #2).
expect_fail "bad_syntax.te" "syntax error" "bad_syntax" "${NEGDIR}/bad_syntax.te"
expect_fail "unknown_perm.te" "permission circular_ref is not defined" "unknown_perm" "${NEGDIR}/unknown_perm.te"
expect_fail "unknown_type.te" "unknown type undeclared_t" "unknown_type" "${NEGDIR}/unknown_type.te"
expect_fail "unknown_class.te" "unknown class not_a_class" "unknown_class" "${NEGDIR}/unknown_class.te"
expect_fail "bad_module_line.te" "syntax error" "bad_module_line" "${NEGDIR}/bad_module_line.te"
expect_fail "bad_require.te" "syntax error" "bad_require" "${NEGDIR}/bad_require.te"
expect_fail "invalid_module_version.te" "syntax error" "invalid_module_version" "${NEGDIR}/invalid_module_version.te"
expect_fail "dup_module.te" "syntax error" "dup_module" "${NEGDIR}/dup_module.te"
expect_fail "dup_type.te" "Duplicate declaration of type" "dup_type" "${NEGDIR}/dup_type.te"
expect_fail "dup_attribute.te" "Duplicate declaration of type" "dup_attribute" \
	"${NEGDIR}/dup_attribute.te"
expect_fail "type_attr_conflict.te" "Duplicate declaration of type" "type_attr_conflict" \
	"${NEGDIR}/type_attr_conflict.te"
expect_fail "invalid_type_name.te" "syntax error" "invalid_type_name" \
	"${NEGDIR}/invalid_type_name.te"
expect_fail "bad_role.te" "syntax error" "bad_role" "${NEGDIR}/bad_role.te"
expect_fail "bad_user.te" "garbage_token" "bad_user" "${NEGDIR}/bad_user.te"

# Missing / bad-path .te inputs (PDF #1).
expect_fail "missing .te path" "unable to open" "missing_path" "${OUTDIR}/does_not_exist.te"
expect_fail "directory instead of .te file" "input in flex scanner failed" "directory_input" "${NEGDIR}"
expect_fail "broken symlink to .te" "unable to open" "broken_symlink" "${OUTDIR}/broken_symlink.te"
expect_fail_unreadable
expect_fail "empty .te path argument" "unable to open" "empty_path" ""

# CLI edge cases.
expect_fail "checkmodule with no input file" "unable to open policy.conf" "no_input"
expect_fail "checkmodule -o name mismatch" "Module name good_module is different" "name_mismatch" \
	-o "${OUTDIR}/wrong_name.mod" "${NEGDIR}/good_module.te"

echo "checkmodule negative tests: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne 0 ]; then
	exit 1
fi
