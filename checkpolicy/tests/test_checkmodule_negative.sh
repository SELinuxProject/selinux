#!/bin/sh
#
# Negative / bad-data tests for checkmodule on module (.te) inputs.
# Matches the modular policy compile path: checkmodule -M -m <input> -o <module>.mod
#
# Size / resource robustness: generated fixtures; scale via LARGE_TE_ALLOWS,
# LARGE_CONF_ALLOWS, HUGE_ATTR_TYPES, or BAD_DATA_STRESS=1 for heavier runs.
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
CHECKPOLICY="${BASEDIR}/../checkpolicy"
OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/checkmodule-negative.XXXXXX")
PASS=0
FAIL=0

LARGE_TE_ALLOWS="${LARGE_TE_ALLOWS:-5000}"
LARGE_CONF_ALLOWS="${LARGE_CONF_ALLOWS:-5000}"
HUGE_ATTR_TYPES="${HUGE_ATTR_TYPES:-2000}"

if [ "${BAD_DATA_STRESS:-0}" = "1" ]; then
	LARGE_TE_ALLOWS=10000
	LARGE_CONF_ALLOWS=10000
	HUGE_ATTR_TYPES=5000
fi

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
		return 0
	fi
	if [ ! -s "${outmod}" ]; then
		echo "FAIL: expected non-empty ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 0
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
		return 0
	fi
	if [ -f "${outmod}" ]; then
		echo "FAIL: did not expect output module ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi
	if ! grep -Eq "${pattern}" "${stderr}"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
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
		return 0
	fi
	if [ -f "${outmod}" ]; then
		echo "FAIL: did not expect output module ${outmod}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi
	if ! grep -Eq 'unable to open|Permission denied' "${stderr}"; then
		echo "FAIL: stderr did not mention unable to open or Permission denied" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	echo "==== ${desc}: rejected as expected"
	PASS=$((PASS + 1))
	echo ""
}

robust_exit_is_crash() {
	rc="$1"

	# Fatal signals (128+N): ILL(132), ABRT(134), BUS(135), FPE(136),
	# KILL(137, includes OOM-kill), SEGV(139).
	case "${rc}" in
	132|134|135|136|137|139)
		return 0
		;;
	esac
	return 1
}

expect_robust() {
	desc="$1"
	timeout_sec="$2"
	outartifact="$3"
	shift 3

	tag=$(echo "${desc}" | tr ' /.' '___')
	stderr="${OUTDIR}/${tag}.err"

	echo "==== ROBUST (expect no crash/hang): ${desc}"
	rm -f "${outartifact}"

	if ! command -v timeout >/dev/null 2>&1; then
		echo "FAIL: timeout(1) required for robustness tests" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	set +e
	timeout "${timeout_sec}" "$@" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 124 ]; then
		echo "FAIL: timed out after ${timeout_sec}s" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi
	if robust_exit_is_crash "${rc}"; then
		echo "FAIL: crashed with rc=${rc}" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi
	if [ "${rc}" -eq 0 ]; then
		if [ ! -s "${outartifact}" ]; then
			echo "FAIL: expected non-empty ${outartifact} on success" >&2
			cat "${stderr}" >&2
			FAIL=$((FAIL + 1))
			return 0
		fi
		echo "==== ${desc}: finished (rc=0, output produced)"
	else
		if [ -f "${outartifact}" ]; then
			echo "FAIL: did not expect output ${outartifact} on rc=${rc}" >&2
			cat "${stderr}" >&2
			FAIL=$((FAIL + 1))
			return 0
		fi
		echo "==== ${desc}: finished safely (rc=${rc}, no output)"
	fi
	PASS=$((PASS + 1))
	echo ""
}

generate_large_module_te() {
	outte="$1"
	count="$2"

	{
		echo 'module large_module 1.0;'
		echo 'require {'
		echo '	type a_t, b_t;'
		echo '	class file { read };'
		echo '}'
		i=0
		while [ "${i}" -lt "${count}" ]; do
			echo 'allow a_t b_t:file read;'
			i=$((i + 1))
		done
	} > "${outte}"
}

generate_large_conf() {
	outconf="$1"
	count="$2"

	{
		echo '# handle_unknown deny'
		echo 'class CLASS1'
		echo 'sid kernel'
		echo 'class CLASS1 { PERM1 }'
		echo 'type TYPE1;'
		echo 'type TYPE2;'
		i=0
		while [ "${i}" -lt "${count}" ]; do
			echo 'allow TYPE1 TYPE2:CLASS1 { PERM1 };'
			i=$((i + 1))
		done
		echo 'role ROLE1;'
		echo 'role ROLE1 types { TYPE1 };'
		echo 'user USER1 roles { ROLE1 };'
		echo 'sid kernel USER1:ROLE1:TYPE1'
	} > "${outconf}"
}

generate_huge_attr_te() {
	outte="$1"
	count="$2"

	{
		echo 'module huge_attr 1.0;'
		echo 'require {'
		echo '	class file { read };'
		i=0
		while [ "${i}" -lt "${count}" ]; do
			echo "	type a${i}_t;"
			i=$((i + 1))
		done
		echo '}'
		echo 'attribute big_attr;'
		i=0
		while [ "${i}" -lt "${count}" ]; do
			echo "typeattribute a${i}_t big_attr;"
			i=$((i + 1))
		done
		echo 'allow a0_t a1_t:file read;'
	} > "${outte}"
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

# Corrupted .te content.
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

# Missing / bad-path .te inputs.
expect_fail "missing .te path" "unable to open" "missing_path" "${OUTDIR}/does_not_exist.te"
expect_fail "directory instead of .te file" "input in flex scanner failed" "directory_input" "${NEGDIR}"
expect_fail "broken symlink to .te" "unable to open" "broken_symlink" "${OUTDIR}/broken_symlink.te"
expect_fail_unreadable
expect_fail "empty .te path argument" "unable to open" "empty_path" ""

# CLI edge cases.
expect_fail "checkmodule with no input file" "unable to open policy.conf" "no_input"
expect_fail "checkmodule -o name mismatch" "Module name good_module is different" "name_mismatch" \
	-o "${OUTDIR}/wrong_name.mod" "${NEGDIR}/good_module.te"

# Size / resource robustness (generated fixtures).
generate_large_module_te "${OUTDIR}/large_module.te" "${LARGE_TE_ALLOWS}"
expect_robust "very large .te module (${LARGE_TE_ALLOWS} allow rules)" 120 \
	"${OUTDIR}/large_module.mod" \
	"${CHECKMODULE}" -M -m -o "${OUTDIR}/large_module.mod" "${OUTDIR}/large_module.te"

generate_large_conf "${OUTDIR}/large.conf" "${LARGE_CONF_ALLOWS}"
expect_robust "very large .conf policy (${LARGE_CONF_ALLOWS} allow rules)" 120 \
	"${OUTDIR}/large.bin" \
	"${CHECKPOLICY}" -E -o "${OUTDIR}/large.bin" "${OUTDIR}/large.conf"

generate_huge_attr_te "${OUTDIR}/huge_attr.te" "${HUGE_ATTR_TYPES}"
expect_robust "huge attribute set (${HUGE_ATTR_TYPES} types)" 120 \
	"${OUTDIR}/huge_attr.mod" \
	"${CHECKMODULE}" -M -m -o "${OUTDIR}/huge_attr.mod" "${OUTDIR}/huge_attr.te"

echo "checkmodule negative tests: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne 0 ]; then
	exit 1
fi
