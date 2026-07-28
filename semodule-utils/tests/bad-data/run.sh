#!/bin/sh
#
# Bad-data tests for semodule_package and sefcontext_compile in the modular
# policy packaging pipeline. Covers packaging path edge cases (-m/-f), documents
# deferred rejection of bad .mod.fc content at packaging time, and validates
# labeling through sefcontext_compile. Unreadable -m/-f cases skip when run as
# root; CI runs this script as non-root.
#

set -u

# Prefer an absolute script dir, but keep a relative dirname when cd fails.
# Non-root CI can inherit the repo as CWD without being able to traverse
# /home/runner/work/...; relative paths from that CWD still work.
BASEDIR=$(dirname -- "$0")
ABS_BASEDIR=$(CDPATH= cd -- "${BASEDIR}" 2>/dev/null && pwd) || ABS_BASEDIR=
if [ -n "${ABS_BASEDIR}" ]; then
	BASEDIR="${ABS_BASEDIR}"
fi
FIXTURES="${BASEDIR}/fixtures"
if [ ! -d "${FIXTURES}" ]; then
	echo "FAIL: cannot resolve fixtures directory (\$0=$0 BASEDIR=${BASEDIR})" >&2
	exit 1
fi
OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/semodule-package-bad-data.XXXXXX")
PASS=0
FAIL=0

CHECKMODULE=${CHECKMODULE:-checkmodule}
# Modular TE for MCS/MLS builds (checkmodule -M -m).
CHECKMODULE_MOD_FLAGS=${CHECKMODULE_MOD_FLAGS:--M -m}
SEMODULE_PACKAGE=${SEMODULE_PACKAGE:-semodule_package}
SEMODULE_UNPACKAGE=${SEMODULE_UNPACKAGE:-semodule_unpackage}
SEFCONTEXT_COMPILE=${SEFCONTEXT_COMPILE:-sefcontext_compile}

GOOD_TE="${FIXTURES}/modules/good.te"
GOOD_MOD="${OUTDIR}/test_good.mod"

cleanup() {
	rm -rf "${OUTDIR}"
}
trap cleanup EXIT

die() {
	echo "FAIL: $*" >&2
	FAIL=$((FAIL + 1))
}

pass() {
	echo "==== $*"
	PASS=$((PASS + 1))
	echo ""
}

build_good_mod() {
	echo "==== Setup: build control module ${GOOD_MOD} from good.te"
	rm -f "${GOOD_MOD}"

	set +e
	# shellcheck disable=SC2086
	"${CHECKMODULE}" ${CHECKMODULE_MOD_FLAGS} -o "${GOOD_MOD}" "${GOOD_TE}" \
		2>"${OUTDIR}/build_good.err"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: could not build control module from ${GOOD_TE}" >&2
		cat "${OUTDIR}/build_good.err" >&2
		exit 1
	fi
	if [ ! -s "${GOOD_MOD}" ]; then
		echo "FAIL: ${GOOD_MOD} is empty" >&2
		exit 1
	fi
	echo ""
}

expect_package_pass() {
	desc="$1"
	outname="$2"
	shift 2

	outpp="${OUTDIR}/${outname}.pp"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== POSITIVE (expect semodule_package success): ${desc}"
	rm -f "${outpp}"

	set +e
	"${SEMODULE_PACKAGE}" -o "${outpp}" "$@" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		echo "stderr:" >&2
		cat "${stderr}" >&2
		die "${desc}: expected exit 0, got rc=${rc}"
		return 0
	fi
	if [ ! -s "${outpp}" ]; then
		die "${desc}: expected non-empty ${outpp}"
		return 0
	fi

	pass "${desc} (exit 0, .pp created)"
}

expect_package_pass_deferred() {
	desc="$1"
	outname="$2"
	shift 2

	outpp="${OUTDIR}/${outname}.pp"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== DOCUMENT (semodule_package accepts input; validate in sefcontext_compile): ${desc}"
	rm -f "${outpp}"

	set +e
	"${SEMODULE_PACKAGE}" -o "${outpp}" "$@" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		echo "stderr:" >&2
		cat "${stderr}" >&2
		die "${desc}: expected exit 0 at packaging stage, got rc=${rc}"
		return 0
	fi
	if [ ! -s "${outpp}" ]; then
		die "${desc}: expected non-empty ${outpp} at packaging stage"
		return 0
	fi

	pass "${desc} (packaging exit 0; labeling validation deferred to sefcontext_compile)"
}

expect_package_fail() {
	desc="$1"
	pattern="$2"
	outname="$3"
	shift 3

	outpp="${OUTDIR}/${outname}.pp"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== NEGATIVE (expect semodule_package failure): ${desc}"
	rm -f "${outpp}"

	set +e
	"${SEMODULE_PACKAGE}" -o "${outpp}" "$@" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero exit, got rc=0"
		return 0
	fi
	if [ -f "${outpp}" ]; then
		die "${desc}: did not expect output ${outpp}"
		return 0
	fi
	if ! grep -Eq "${pattern}" "${stderr}"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (rejected as expected, rc=${rc})"
}

expect_package_fail_unreadable() {
	desc="unreadable -m file"
	mod="${OUTDIR}/unreadable.mod"
	outpp="${OUTDIR}/unreadable.pp"
	stderr="${OUTDIR}/unreadable.err"

	echo "==== NEGATIVE (expect semodule_package failure): ${desc}"
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIP: root can read mode 000 files; unreadable check is non-root only"
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	rm -f "${outpp}"
	cp "${GOOD_MOD}" "${mod}"
	chmod 000 "${mod}"

	set +e
	"${SEMODULE_PACKAGE}" -o "${outpp}" -m "${mod}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero exit, got rc=0"
		return 0
	fi
	if [ -f "${outpp}" ]; then
		die "${desc}: did not expect output ${outpp}"
		return 0
	fi
	if ! grep -Eq 'Permission denied|Could not open|Failed to open' "${stderr}"; then
		echo "FAIL: stderr did not mention permission or open failure" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (rejected as expected, rc=${rc})"
}

expect_package_fail_unreadable_fc() {
	desc="unreadable -f file"
	fc="${OUTDIR}/unreadable.mod.fc"
	outpp="${OUTDIR}/unreadable_fc.pp"
	stderr="${OUTDIR}/unreadable_fc.err"

	echo "==== NEGATIVE (expect semodule_package failure): ${desc}"
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIP: root can read mode 000 files; unreadable check is non-root only"
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	rm -f "${outpp}"
	cp "${GOOD_FC}" "${fc}"
	chmod 000 "${fc}"

	set +e
	"${SEMODULE_PACKAGE}" -o "${outpp}" -m "${GOOD_MOD}" -f "${fc}" \
		2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero exit, got rc=0"
		return 0
	fi
	if [ -f "${outpp}" ]; then
		die "${desc}: did not expect output ${outpp}"
		return 0
	fi
	if ! grep -Eq 'Permission denied|Could not open|Failed to open' "${stderr}"; then
		echo "FAIL: stderr did not mention permission or open failure" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (rejected as expected, rc=${rc})"
}

find_policy_file() {
	if [ -n "${POLICY_FILE:-}" ] && [ -f "${POLICY_FILE}" ]; then
		echo "${POLICY_FILE}"
		return 0
	fi

	# Prefer the active policy store (SELINUXTYPE); fall back to targeted, then any
	# installed policy.* (POLICY_FILE overrides all of this).
	selinuxtype=targeted
	if [ -r /etc/selinux/config ]; then
		selinuxtype=$(grep -E '^[[:space:]]*SELINUXTYPE=' /etc/selinux/config 2>/dev/null \
			| tail -1 | cut -d= -f2- | tr -d ' "')
		[ -n "${selinuxtype}" ] || selinuxtype=targeted
	fi

	# shellcheck disable=SC2086
	set -- /etc/selinux/"${selinuxtype}"/policy/policy.*
	if [ -f "$1" ]; then
		echo "$1"
		return 0
	fi

	for policy in /etc/selinux/*/policy/policy.*; do
		[ -f "${policy}" ] || continue
		echo "${policy}"
		return 0
	done

	return 1
}

expect_sefcontext_pass() {
	desc="$1"
	outname="$2"
	fc="$3"
	policy="${4:-}"

	outbin="${OUTDIR}/${outname}.bin"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== POSITIVE (expect sefcontext_compile success): ${desc}"
	rm -f "${outbin}"

	set +e
	if [ -n "${policy}" ]; then
		"${SEFCONTEXT_COMPILE}" -p "${policy}" -o "${outbin}" "${fc}" \
			2>"${stderr}"
	else
		"${SEFCONTEXT_COMPILE}" -o "${outbin}" "${fc}" 2>"${stderr}"
	fi
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected exit 0, got rc=${rc}"
		return 0
	fi
	if [ ! -s "${outbin}" ]; then
		die "${desc}: expected non-empty ${outbin}"
		return 0
	fi

	pass "${desc} (sefcontext_compile succeeded)"
}

expect_sefcontext_fail() {
	desc="$1"
	pattern="$2"
	outname="$3"
	fc="$4"
	policy="${5:-}"

	outbin="${OUTDIR}/${outname}.bin"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== NEGATIVE (expect sefcontext_compile failure): ${desc}"
	rm -f "${outbin}"

	set +e
	if [ -n "${policy}" ]; then
		"${SEFCONTEXT_COMPILE}" -p "${policy}" -o "${outbin}" "${fc}" \
			2>"${stderr}"
	else
		"${SEFCONTEXT_COMPILE}" -o "${outbin}" "${fc}" 2>"${stderr}"
	fi
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero exit, got rc=0"
		return 0
	fi
	if [ -f "${outbin}" ] && [ -s "${outbin}" ]; then
		die "${desc}: did not expect successful ${outbin}"
		return 0
	fi
	if ! grep -Eq "${pattern}" "${stderr}"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${stderr}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (rejected as expected, rc=${rc})"
}

expect_sefcontext_fail_or_skip_no_policy() {
	desc="$1"
	pattern="$2"
	outname="$3"
	fc="$4"

	policy=$(find_policy_file) || policy=
	if [ -z "${policy}" ]; then
		echo "==== SKIP (no binary policy for -p validation): ${desc}"
		echo "Set POLICY_FILE= to enable this check."
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	expect_sefcontext_fail "${desc}" "${pattern}" "${outname}" "${fc}" \
		"${policy}"
}

expect_sefcontext_pass_deferred() {
	desc="$1"
	outname="$2"
	fc="$3"

	outbin="${OUTDIR}/${outname}.bin"
	stderr="${OUTDIR}/${outname}.err"

	echo "==== DOCUMENT (sefcontext_compile accepts input; complements packaging deferral): ${desc}"
	rm -f "${outbin}"

	set +e
	"${SEFCONTEXT_COMPILE}" -o "${outbin}" "${fc}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected exit 0 at compile stage, got rc=${rc}"
		return 0
	fi
	if [ ! -s "${outbin}" ]; then
		die "${desc}: expected non-empty ${outbin} at compile stage"
		return 0
	fi

	pass "${desc} (sefcontext_compile exit 0; complements packaging deferral)"
}

build_good_mod

# Ephemeral path fixtures for packaging path tests.
ln -sf /nonexistent/test_good.mod "${OUTDIR}/broken_symlink.mod"
ln -sf /nonexistent/test_good.mod.fc "${OUTDIR}/broken_symlink.mod.fc"
printf '' > "${OUTDIR}/empty.mod.fc"

# NUL byte inside path column (packaging accepts; sefcontext_compile rejects).
printf '/bin/foo\000bar\t--\tsystem_u:object_r:test_good_exec_t:s0\n' \
	> "${OUTDIR}/nul_bytes.mod.fc"

GOOD_FC="${FIXTURES}/file_contexts/good.mod.fc"

# --- semodule_package input paths ---
expect_package_pass \
	"control good .mod without file contexts" \
	good_mod \
	-m "${GOOD_MOD}"

expect_package_pass \
	"control good .mod with good .mod.fc" \
	good_mod_fc \
	-m "${GOOD_MOD}" -f "${GOOD_FC}"

expect_package_fail \
	"missing -m path" \
	"Could not open|Failed to open" \
	missing_mod \
	-m "${OUTDIR}/does_not_exist.mod"

expect_package_fail \
	"missing -f path" \
	"Failed to open|Could not open" \
	missing_fc \
	-m "${GOOD_MOD}" -f "${OUTDIR}/does_not_exist.mod.fc"

expect_package_fail \
	"directory instead of -m file" \
	"Error while reading policy module|Could not open" \
	directory_mod \
	-m "${BASEDIR}"

expect_package_fail \
	"broken symlink for -m" \
	"Could not open|Failed to open|No such file" \
	symlink_mod \
	-m "${OUTDIR}/broken_symlink.mod"

expect_package_fail_unreadable

expect_package_fail \
	"empty -m path argument" \
	"Could not open|Failed to open" \
	empty_mod \
	-m ""

expect_package_fail \
	"directory instead of -f file" \
	"Permission denied|Failed to mmap|Failed to open|Could not open" \
	directory_fc \
	-m "${GOOD_MOD}" -f "${BASEDIR}"

expect_package_fail \
	"broken symlink for -f" \
	"Could not open|Failed to open|No such file" \
	symlink_fc \
	-m "${GOOD_MOD}" -f "${OUTDIR}/broken_symlink.mod.fc"

expect_package_fail_unreadable_fc

expect_package_fail \
	"empty -f path argument" \
	"Could not open|Failed to open" \
	empty_fc_arg \
	-m "${GOOD_MOD}" -f ""

# --- bad .mod.fc at packaging time ---
expect_package_pass_deferred \
	"invalid SELinux context in .mod.fc" \
	bad_context \
	-m "${GOOD_MOD}" -f "${FIXTURES}/file_contexts/bad_context.mod.fc"

expect_package_pass_deferred \
	"wrong field count in .mod.fc" \
	bad_fields \
	-m "${GOOD_MOD}" -f "${FIXTURES}/file_contexts/bad_fields.mod.fc"

expect_package_pass_deferred \
	"NUL byte in .mod.fc path field" \
	nul_bytes \
	-m "${GOOD_MOD}" -f "${OUTDIR}/nul_bytes.mod.fc"

expect_package_pass_deferred \
	"empty .mod.fc file" \
	empty_fc \
	-m "${GOOD_MOD}" -f "${OUTDIR}/empty.mod.fc"

# --- sefcontext_compile / unpackage validation ---
expect_sefcontext_pass \
	"control good .mod.fc through sefcontext_compile" \
	good_fc \
	"${GOOD_FC}"

expect_sefcontext_fail \
	"wrong field count in .mod.fc (after packaging)" \
	"missing fields|process_file failed" \
	sefcontext_bad_fields \
	"${FIXTURES}/file_contexts/bad_fields.mod.fc"

expect_sefcontext_fail \
	"NUL byte in .mod.fc path field (after packaging)" \
	"missing fields|process_file failed" \
	sefcontext_nul_bytes \
	"${OUTDIR}/nul_bytes.mod.fc"

expect_sefcontext_fail_or_skip_no_policy \
	"invalid SELinux context requires policy validation (-p)" \
	"invalid context|malformed context|process_file failed" \
	sefcontext_bad_context \
	"${FIXTURES}/file_contexts/bad_context.mod.fc"

expect_sefcontext_pass_deferred \
	"empty .mod.fc file through sefcontext_compile" \
	sefcontext_empty_fc \
	"${OUTDIR}/empty.mod.fc"

expect_sefcontext_fail_or_skip_no_policy \
	"invalid MLS context requires policy validation (-p)" \
	"invalid context|malformed context|process_file failed" \
	sefcontext_bad_mls \
	"${FIXTURES}/file_contexts/bad_mls.mod.fc"

BAD_PP="${OUTDIR}/bad_context.pp"
EXTRACTED_MOD="${OUTDIR}/extracted.mod"
EXTRACTED_FC="${OUTDIR}/extracted.fc"

echo "==== Setup: extract file contexts from packaged module with invalid context"
rm -f "${EXTRACTED_MOD}" "${EXTRACTED_FC}"
set +e
"${SEMODULE_UNPACKAGE}" "${BAD_PP}" "${EXTRACTED_MOD}" "${EXTRACTED_FC}" \
	2>"${OUTDIR}/unpackage.err"
rc=$?
set -e
if [ "${rc}" -ne 0 ] || [ ! -s "${EXTRACTED_FC}" ]; then
	die "unpackage setup: could not extract .fc from ${BAD_PP}"
	cat "${OUTDIR}/unpackage.err" >&2
else
	echo "==== unpackage setup succeeded"
	echo ""
	expect_sefcontext_fail_or_skip_no_policy \
		"invalid context from unpackage'd .pp file contexts" \
		"invalid context|malformed context|process_file failed" \
		unpackaged_bad_context \
		"${EXTRACTED_FC}"
fi

echo "========================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne 0 ]; then
	exit 1
fi
exit 0
