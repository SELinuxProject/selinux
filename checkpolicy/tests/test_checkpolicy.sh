#!/bin/sh

set -eu

BASEDIR=$(dirname "$0")
CHECKPOLICY="${BASEDIR}/../checkpolicy"

check_policy() {
	POLICY=$1
	MLS=$2

	if [ "$MLS" = 'mls' ]; then
		OPT='-M'
	else
		OPT=
	fi

	echo "==== Testing ${1}"

	set -x

	${CHECKPOLICY} ${OPT} -E "${BASEDIR}/${POLICY}" -o testpol.bin
	${CHECKPOLICY} ${OPT} -E -b -F testpol.bin -o testpol.conf
	diff -u "${BASEDIR}/${POLICY}" testpol.conf

	${CHECKPOLICY} ${OPT} -S -O -E "${BASEDIR}/${POLICY}" -o testpol.bin
	${CHECKPOLICY} ${OPT} -S -O -E -b -F testpol.bin -o testpol.conf
	diff -u "${BASEDIR}/${POLICY}" testpol.conf

	{ set +x; } 2>/dev/null

	echo "==== ${1} success"
}


check_policy polmin.conf std
check_policy polmin.mls.conf mls
