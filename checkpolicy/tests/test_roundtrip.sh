#!/bin/sh

set -eu

BASEDIR=$(dirname "$0")
CHECKPOLICY="${BASEDIR}/../checkpolicy"

check_policy() {
	POLICY=$1
	EXPECTED=$2
	OPTS=$3

	echo "==== Testing ${1}"

	${CHECKPOLICY} ${OPTS} "${BASEDIR}/${POLICY}" -o "${BASEDIR}/testpol.bin"
	${CHECKPOLICY} ${OPTS} -b -F "${BASEDIR}/testpol.bin" -o "${BASEDIR}/testpol.conf"
	diff -u "${BASEDIR}/${EXPECTED}" "${BASEDIR}/testpol.conf"

	${CHECKPOLICY} ${OPTS} "${BASEDIR}/${EXPECTED}" -o "${BASEDIR}/testpol.bin"
	${CHECKPOLICY} ${OPTS} -b -F "${BASEDIR}/testpol.bin" -o "${BASEDIR}/testpol.conf"
	diff -u "${BASEDIR}/${EXPECTED}" "${BASEDIR}/testpol.conf"

	echo "==== ${1} success"
	echo ""
}


check_policy  policy_minimal.conf      policy_minimal.conf                   '-E'
check_policy  policy_minimal.conf      policy_minimal.conf                   '-E -S -O'

check_policy  policy_minimal_mls.conf  policy_minimal_mls.conf               '-M -E'
check_policy  policy_minimal_mls.conf  policy_minimal_mls.conf               '-M -E -S -O'

check_policy  policy_allonce.conf      policy_allonce.expected.conf          ''
check_policy  policy_allonce.conf      policy_allonce.expected_opt.conf      '-S -O'

check_policy  policy_allonce_mls.conf  policy_allonce_mls.expected.conf      '-M'
check_policy  policy_allonce_mls.conf  policy_allonce_mls.expected_opt.conf  '-M -S -O'

check_policy  policy_allonce_xen.conf  policy_allonce_xen.expected.conf      '--target xen -c 30 -E'
check_policy  policy_allonce_xen.conf  policy_allonce_xen.expected_opt.conf  '--target xen -c 30 -E -S -O'
