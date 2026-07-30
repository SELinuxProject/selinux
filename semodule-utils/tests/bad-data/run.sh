#!/bin/sh
#
# Bad-data tests for semodule_package, sefcontext_compile, and
# semodule_link/semodule_expand in the modular policy packaging pipeline.
# Covers packaging path edge cases (-m/-f), documents deferred rejection of bad
# .mod.fc content at packaging time, validates labeling through sefcontext_compile,
# and exercises neverallow enforcement at link/expand. Unreadable -m/-f cases skip
# when run as root; CI runs this script as non-root.
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
SEMODULE_LINK=${SEMODULE_LINK:-semodule_link}
SEMODULE_EXPAND=${SEMODULE_EXPAND:-semodule_expand}

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

build_loadable_package() {
	te="$1"
	mod="$2"
	pp="$3"

	set +e
	# Non-MLS modular build to match fixtures/base/minimal_base.conf.
	"${CHECKMODULE}" -m -o "${mod}" "${te}" 2>"${mod}.err"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: checkmodule could not build ${te}" >&2
		cat "${mod}.err" >&2
		exit 1
	fi

	set +e
	"${SEMODULE_PACKAGE}" -o "${pp}" -m "${mod}" 2>"${pp}.err"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: semodule_package could not build ${pp}" >&2
		cat "${pp}.err" >&2
		exit 1
	fi
}

expect_checkmodule_pass() {
	desc="$1"
	te="$2"
	mod="${OUTDIR}/$(basename "${te}" .te).mod"

	echo "==== DOCUMENT (checkmodule accepts module; enforcement deferred to expand): ${desc}"
	rm -f "${mod}" "${mod}.err"

	set +e
	"${CHECKMODULE}" -m -o "${mod}" "${te}" 2>"${mod}.err"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		cat "${mod}.err" >&2
		die "${desc}: expected checkmodule success, got rc=${rc}"
		return 0
	fi
	if [ ! -s "${mod}" ]; then
		die "${desc}: expected non-empty ${mod}"
		return 0
	fi

	pass "${desc} (checkmodule exit 0, .mod created)"
}

# Sets LINK_EXPAND_LINK_RC and LINK_EXPAND_EXPAND_RC (-1 if expand not run).
run_link_expand() {
	link_out="$1"
	expand_out="$2"
	base_pp="$3"
	shift 3

	rm -f "${link_out}" "${expand_out}" "${link_out}.err" "${expand_out}.err"

	set +e
	"${SEMODULE_LINK}" -o "${link_out}" "${base_pp}" "$@" \
		2>"${link_out}.err"
	LINK_EXPAND_LINK_RC=$?
	set -e
	if [ "${LINK_EXPAND_LINK_RC}" -ne 0 ]; then
		cat "${link_out}.err" >&2
		LINK_EXPAND_EXPAND_RC=-1
		return 0
	fi

	set +e
	"${SEMODULE_EXPAND}" "${link_out}" "${expand_out}" \
		2>"${expand_out}.err"
	LINK_EXPAND_EXPAND_RC=$?
	set -e
	if [ "${LINK_EXPAND_EXPAND_RC}" -ne 0 ]; then
		cat "${expand_out}.err" >&2
	fi
}

expect_link_expand_pass() {
	desc="$1"
	link_out="$2"
	expand_out="$3"
	base_pp="$4"
	shift 4

	echo "==== POSITIVE (expect link + expand success): ${desc}"
	run_link_expand "${link_out}" "${expand_out}" "${base_pp}" "$@"
	if [ "${LINK_EXPAND_LINK_RC}" -ne 0 ]; then
		die "${desc}: semodule_link failed, rc=${LINK_EXPAND_LINK_RC}"
		return 0
	fi
	if [ "${LINK_EXPAND_EXPAND_RC}" -ne 0 ]; then
		die "${desc}: semodule_expand failed, rc=${LINK_EXPAND_EXPAND_RC}"
		return 0
	fi
	if [ ! -s "${expand_out}" ]; then
		die "${desc}: expected non-empty ${expand_out}"
		return 0
	fi

	pass "${desc} (link and expand succeeded)"
}

expect_link_expand_fail() {
	desc="$1"
	pattern="$2"
	link_out="$3"
	expand_out="$4"
	base_pp="$5"
	shift 5

	echo "==== NEGATIVE (expect neverallow failure at expand): ${desc}"
	run_link_expand "${link_out}" "${expand_out}" "${base_pp}" "$@"
	if [ "${LINK_EXPAND_LINK_RC}" -ne 0 ]; then
		die "${desc}: expected semodule_link success before expand, rc=${LINK_EXPAND_LINK_RC}"
		return 0
	fi
	if [ "${LINK_EXPAND_EXPAND_RC}" -eq 0 ]; then
		die "${desc}: expected semodule_expand failure, got rc=0"
		return 0
	fi
	if ! grep -Eq "${pattern}" "${expand_out}.err"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${expand_out}.err" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (expand failed on neverallow as expected, rc=${LINK_EXPAND_EXPAND_RC})"
}

# Same-module neverallowxperm: enforced at expand on libsepol 3.11+, deferred on older userspace.
expect_link_expand_fail_or_deferred() {
	desc="$1"
	pattern="$2"
	link_out="$3"
	expand_out="$4"
	base_pp="$5"
	shift 5

	echo "==== NEGATIVE or DOCUMENT (same-module neverallowxperm at expand): ${desc}"
	run_link_expand "${link_out}" "${expand_out}" "${base_pp}" "$@"
	if [ "${LINK_EXPAND_LINK_RC}" -ne 0 ]; then
		die "${desc}: expected semodule_link success, rc=${LINK_EXPAND_LINK_RC}"
		return 0
	fi
	if [ "${LINK_EXPAND_EXPAND_RC}" -eq 0 ]; then
		if [ ! -s "${expand_out}" ]; then
			die "${desc}: expected non-empty ${expand_out} when expand deferred"
			return 0
		fi
		pass "${desc} (link and expand succeeded; enforcement deferred on this userspace)"
		return 0
	fi
	if ! grep -Eq "${pattern}" "${expand_out}.err"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${expand_out}.err" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (expand failed on neverallowxperm as expected, rc=${LINK_EXPAND_EXPAND_RC})"
}

build_base_package() {
	base_conf="$1"
	base_mod="$2"
	base_pp="$3"

	set +e
	"${CHECKMODULE}" -o "${base_mod}" "${base_conf}" 2>"${base_mod}.err"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: checkmodule could not build base from ${base_conf}" >&2
		cat "${base_mod}.err" >&2
		exit 1
	fi

	set +e
	"${SEMODULE_PACKAGE}" -o "${base_pp}" -m "${base_mod}" 2>"${base_pp}.err"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		echo "FAIL: semodule_package could not build ${base_pp}" >&2
		cat "${base_pp}.err" >&2
		exit 1
	fi
}

expect_link_fail() {
	desc="$1"
	pattern="$2"
	link_out="$3"
	base_pp="$4"
	shift 4

	echo "==== NEGATIVE (expect semodule_link failure): ${desc}"
	rm -f "${link_out}" "${link_out}.err"

	set +e
	"${SEMODULE_LINK}" -o "${link_out}" "${base_pp}" "$@" \
		2>"${link_out}.err"
	rc=$?
	set -e
	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected semodule_link failure, got rc=0"
		return 0
	fi
	if ! grep -Eq "${pattern}" "${link_out}.err"; then
		echo "FAIL: stderr did not match /${pattern}/" >&2
		cat "${link_out}.err" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (link failed on unmet require as expected, rc=${rc})"
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

# --- semodule_link / semodule_expand neverallow ---
BASE_CONF="${FIXTURES}/base/minimal_base.conf"
BASE_MOD="${OUTDIR}/minimal_base.mod"
BASE_PP="${OUTDIR}/minimal_base.pp"
GOOD_LOADABLE_MOD="${OUTDIR}/neverallow_good.mod"
GOOD_LOADABLE_PP="${OUTDIR}/neverallow_good.pp"
VIOLATOR_MOD="${OUTDIR}/neverallow_violator.mod"
VIOLATOR_PP="${OUTDIR}/neverallow_violator.pp"
SELF_MOD="${OUTDIR}/neverallow_self.mod"
SELF_PP="${OUTDIR}/neverallow_self.pp"
XPERM_VIOLATOR_MOD="${OUTDIR}/neverallow_xperm_violator.mod"
XPERM_VIOLATOR_PP="${OUTDIR}/neverallow_xperm_violator.pp"
XPERM_SELF_MOD="${OUTDIR}/neverallow_xperm_self.mod"
XPERM_SELF_PP="${OUTDIR}/neverallow_xperm_self.pp"

echo "==== Setup: build minimal base and loadable module packages (non-MLS)"
build_base_package "${BASE_CONF}" "${BASE_MOD}" "${BASE_PP}"
build_loadable_package "${FIXTURES}/modules/neverallow_good.te" \
	"${GOOD_LOADABLE_MOD}" "${GOOD_LOADABLE_PP}"
build_loadable_package "${FIXTURES}/modules/neverallow_violator.te" \
	"${VIOLATOR_MOD}" "${VIOLATOR_PP}"
build_loadable_package "${FIXTURES}/modules/neverallow_self.te" \
	"${SELF_MOD}" "${SELF_PP}"
build_loadable_package "${FIXTURES}/modules/neverallow_xperm_violator.te" \
	"${XPERM_VIOLATOR_MOD}" "${XPERM_VIOLATOR_PP}"
build_loadable_package "${FIXTURES}/modules/neverallow_xperm_self.te" \
	"${XPERM_SELF_MOD}" "${XPERM_SELF_PP}"
echo ""

expect_checkmodule_pass \
	"neverallow module passes checkmodule before expand rejects it" \
	"${FIXTURES}/modules/neverallow_self.te"

expect_checkmodule_pass \
	"neverallowxperm module passes checkmodule before link/expand" \
	"${FIXTURES}/modules/neverallow_xperm_self.te"

expect_link_expand_pass \
	"control base + good module link and expand" \
	"${OUTDIR}/link_good.pp" \
	"${OUTDIR}/expand_good.bin" \
	"${BASE_PP}" \
	"${GOOD_LOADABLE_PP}"

expect_link_expand_fail \
	"loadable module violates base neverallow on expand" \
	"neverallow violated|neverallow failures occurred" \
	"${OUTDIR}/link_violator.pp" \
	"${OUTDIR}/expand_violator.bin" \
	"${BASE_PP}" \
	"${VIOLATOR_PP}"

expect_link_expand_fail \
	"same-module neverallow violated on expand" \
	"neverallow violated|neverallow failures occurred" \
	"${OUTDIR}/link_self.pp" \
	"${OUTDIR}/expand_self.bin" \
	"${BASE_PP}" \
	"${SELF_PP}"

expect_link_expand_fail \
	"loadable module violates base neverallowxperm on expand" \
	"neverallowxperm|neverallow failures occurred" \
	"${OUTDIR}/link_xperm_violator.pp" \
	"${OUTDIR}/expand_xperm_violator.bin" \
	"${BASE_PP}" \
	"${XPERM_VIOLATOR_PP}"

expect_link_expand_fail_or_deferred \
	"same-module neverallowxperm violated on expand" \
	"neverallowxperm|neverallow failures occurred" \
	"${OUTDIR}/link_xperm_self.pp" \
	"${OUTDIR}/expand_xperm_self.bin" \
	"${BASE_PP}" \
	"${XPERM_SELF_PP}"

# --- cross-module require (§2c.9) ---
REQUIRE_CONSUMER_MOD="${OUTDIR}/module_a.mod"
REQUIRE_CONSUMER_PP="${OUTDIR}/module_a.pp"
REQUIRE_PROVIDER_MOD="${OUTDIR}/module_b.mod"
REQUIRE_PROVIDER_PP="${OUTDIR}/module_b.pp"

build_loadable_package "${FIXTURES}/modules/module_a.te" \
	"${REQUIRE_CONSUMER_MOD}" "${REQUIRE_CONSUMER_PP}"
build_loadable_package "${FIXTURES}/modules/module_b.te" \
	"${REQUIRE_PROVIDER_MOD}" "${REQUIRE_PROVIDER_PP}"

expect_checkmodule_pass \
	"consumer module passes checkmodule before link rejects missing require" \
	"${FIXTURES}/modules/module_a.te"

expect_link_fail \
	"module requires type only declared in another module" \
	"requirements were not met|global requirements" \
	"${OUTDIR}/link_require_consumer.pp" \
	"${BASE_PP}" \
	"${REQUIRE_CONSUMER_PP}"

expect_link_expand_pass \
	"consumer and provider modules link and expand together" \
	"${OUTDIR}/link_require_both.pp" \
	"${OUTDIR}/expand_require_both.bin" \
	"${BASE_PP}" \
	"${REQUIRE_CONSUMER_PP}" \
	"${REQUIRE_PROVIDER_PP}"

echo "========================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne 0 ]; then
	exit 1
fi
exit 0
