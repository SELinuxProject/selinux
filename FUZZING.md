Fuzzing of the SELinux userspace
================================

OSS-Fuzz
--------

Portions of the SELinux userspace are regularly fuzzed by OSS-Fuzz based
on the configuration at:
https://github.com/google/oss-fuzz/blob/master/projects/selinux/project.yaml

The fuzzers can be found under the fuzz subdirectories of various
directories within the selinux repository, and can be built using the
./scripts/oss-fuzz.sh script. OSS-Fuzz itself uses this script to
build the fuzzers.

See
https://issues.oss-fuzz.com/issues?q=project:selinux
for public OSS-Fuzz selinux issues. OSS-Fuzz automatically makes
issues public once they are verified to be fixed or after a 90 day
disclosure window. Issues are initially created private and
sent via email to those listed in the configuration above.

Not all issues will be fixed by the upstream SELinux project, e.g.
small memory leaks on error paths for checkpolicy are not viewed as
worth fixing since checkpolicy will exit shortly thereafter, and OSS
Fuzz will create issues if it encounters a timeout during fuzzing even
though the fuzzer would have completed if given more time.

Items categorized as a vulnerability by OSS-Fuzz will not always be
treated as security issues by the upstream SELinux project; in
particular, issues that depend on attacker-controlled policy are not
considered to be security issues and will just be handled as regular
bugs. See
[SECURITY.md](https://github.com/SELinuxProject/selinux/blob/main/SECURITY.md)
for more information on the SELinux userspace security vulnerability
handling process.

CIFuzz
------

The selinux GitHub CI Actions include a CIFuzz workflow based on the
configuration at:
https://github.com/SELinuxProject/selinux/blob/main/.github/workflows/cifuzz.yml

This action is invoked for pushes and pull requests targeting the main
branch of the SELinuxProject/selinux repository to help detect
regressions on new commits.

The status of CIFuzz workflow runs can be viewed at:
https://github.com/SELinuxProject/selinux/actions/workflows/cifuzz.yml
as well as in the check status for each push or pull request and
displayed in the banner at the top of the
[README.md](https://github.com/SELinuxProject/selinux/blob/main/README.md)
file.

Debugging Fuzzing Failures
--------------------------

OSS-Fuzz provides a detailed report and, when possible, a reproducer
testcase. If the cause cannot be determined from the report, the
reproducer testcase can be downloaded locally, the fuzzer can be built
using ./scripts/oss-fuzz.sh, and the fuzzer can be manually run on the
reproducer testcase input.

The fuzzers are built without debugging information and with verbose
logging disabled when built using oss-fuzz.sh. You can recompile them
with debugging, logging, and a trivial main() function as follows:

    make CFLAGS+=-g -C libsepol clean fuzz
    make CFLAGS+=-g -C checkpolicy clean fuzz
    make CFLAGS+=-g -C libselinux clean fuzz

These build into the fuzz/ directories and do not touch any object
files or archives used by the normal build.

In some cases, it may be helpful to run one of the selinux userspace
programs on the fuzzer input directly, potentially under gdb or
valgrind, to better understand the issue and whether it is applicable
to any production tool. This can be done when the fuzzer input is
accepted directly as input to one of the selinux userspace programs,
such as a CIL policy file to secilc or a binary policy file to
checkpolicy -b. In other cases you may need to split the fuzzer input
into its parts and only feed one portion to a program like checkpolicy
or selabel_lookup.
