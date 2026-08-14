SELinux Userspace
=================

![SELinux logo](https://github.com/SELinuxProject.png)
[![Run Tests](https://github.com/SELinuxProject/selinux/actions/workflows/run_tests.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/run_tests.yml)
[![Run SELinux testsuite in Testing Farm](https://github.com/SELinuxProject/selinux/actions/workflows/tf_testsuite.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/tf_testsuite.yml)
[![OSS-Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/selinux.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#selinux)
[![CIFuzz Status](https://github.com/SELinuxProject/selinux/actions/workflows/cifuzz.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/cifuzz.yml)
[![Check Format](https://github.com/SELinuxProject/selinux/actions/workflows/check_format.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/check_format.yml)

SELinux is a flexible Mandatory Access Control (MAC) system built into the
Linux Kernel. SELinux provides administrators with a comprehensive access
control mechanism that enables greater access granularity over the existing
Linux Discretionary Access Controls (DAC) and is present in many major Linux
distributions. This repository contains the sources for the SELinux utilities
and system libraries which allow for the configuration and management of an
SELinux-based system.

Please submit all bug reports and patches to the <selinux@vger.kernel.org>
mailing list. You can subscribe by sending an email to <selinux+subscribe@vger.kernel.org>
Archives of the mailing list are available at https://lore.kernel.org/selinux.

See the [SELinux Userspace wiki](https://github.com/SELinuxProject/selinux/wiki)
for more information.

Minimum Supported Kernel Version
--------------------------------
The minimum supported kernel version is Linux v3.0 (for the
/sys/fs/selinux mount point directory) for libselinux and anything
that uses libselinux to access selinuxfs.

Note that the policy build toolchain (e.g. libsepol, checkpolicy,
checkmodule, secilc, semodule_package/expand/link) does not link with
libselinux or have any other runtime dependencies on a particular
Linux kernel version. The policy build toolchain has in the past
successfully been built and run on non-Linux platforms as well
(e.g. macOS), although this is not officially supported.

Minimum Supported Policy Versions
---------------------------------
The minimum kernel policy version is 24 (boundary) for the SELinux and
Xen targets. Support for this policy version first shipped in libsepol
2.0.34 (userspace release 20090403), Linux v2.6.28, and Xen
4.0.0. libsepol dropped support for kernel policy versions older than
24 starting with libsepol 3.12.

The minimum modular policy version is 10 (boundary alias). Support for
this modular policy version first shipped in libsepol 2.0.35
(userspace release 20090403). libsepol dropped support for modular
policies older than 10 starting with libsepol 3.12

These minimum policy versions in libsepol affect:
1. The policy build toolchain. For example, checkpolicy, checkmodule,
and secilc cannot generate a policy with a version less than the
minimum.
2. libselinux and its users. For example, libselinux cannot downgrade a
policy file to a version less than the minimum, and libsemanage cannot
read a binary policy module that was compiled with a version less than
the minimum.
3. SELinux policy analysis tools. For example, setools cannot read a
policy with a version less the minimum.
4. The Xen hypervisor, which compiles its XSM/Flask policies using
checkpolicy, and only currently supports kernel policy versions 24 and
30 for the Xen target. Xen does not use binary policy modules so it is
unaffected by changes to the minimum modular policy version.
5. Android, which is on kernel policy version 30. There has not been
any need for newer policy version features yet. Android does not use
binary policy modules so it is unaffected by changes to the minimum
modular policy version.

Increasing the minimum kernel policy version for libsepol therefore
prevents generating, loading, or analyzing policies for Linux kernels
or Xen hypervisors that only support a kernel policy version lower
than the new minimum. The minimum kernel policy version should only
be increased when there are no still-supported versions of the Linux
kernel and Xen hypervisor that require a lower kernel policy version.

Increasing the minimum modular policy version for libsepol prevents
generating binary modules for distribution releases that only support
a modular policy version lower than the new minimum, and also prevents
reading and hence using binary modules that were built with a version
lower than the new minimum. This could affect modules originally built
under an older release and carried forward through system upgrades.
The minimum modular policy version should only be increased when there
are no still-supported Linux distributions that require a lower
modular policy version _and_ any binary modules carried forward
through system upgrades can reasonably be assumed to have required a
rebuild anyway due to major changes to the system policy headers.

Installation
------------

SELinux libraries and tools are packaged in several Linux distributions:

* Alpine Linux (https://pkgs.alpinelinux.org/package/edge/testing/x86/policycoreutils)
* Arch Linux User Repository (https://aur.archlinux.org/packages/policycoreutils/)
* Buildroot (https://git.buildroot.net/buildroot/tree/package/policycoreutils)
* Debian and Ubuntu (https://packages.debian.org/sid/policycoreutils)
* Gentoo (https://packages.gentoo.org/packages/sys-apps/policycoreutils)
* RHEL and Fedora (https://src.fedoraproject.org/rpms/policycoreutils)
* SLES and openSUSE (https://src.opensuse.org/pool/policycoreutils)
* Yocto Project (http://git.yoctoproject.org/cgit/cgit.cgi/meta-selinux/tree/recipes-security/selinux)
* and many more (https://repology.org/project/policycoreutils/versions)


Building and testing
--------------------

Build dependencies on Fedora:

```sh
# For C libraries and programs
dnf install \
    audit-libs-devel \
    bison \
    bzip2-devel \
    CUnit-devel \
    diffutils \
    flex \
    gcc \
    gettext \
    glib2-devel \
    make \
    libcap-devel \
    libcap-ng-devel \
    pam-devel \
    pcre2-devel \
    xmlto

# For Python and Ruby bindings
dnf install \
    python3-build \
    python3-devel \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    ruby-devel \
    swig
```

Build dependencies on Debian:

```sh
# For C libraries and programs
apt-get install --no-install-recommends --no-install-suggests \
    bison \
    flex \
    gawk \
    gcc \
    gettext \
    make \
    libaudit-dev \
    libbz2-dev \
    libcap-dev \
    libcap-ng-dev \
    libcunit1-dev \
    libglib2.0-dev \
    libpcre2-dev \
    pkgconf \
    python3 \
    systemd \
    xmlto

# For Python and Ruby bindings
apt-get install --no-install-recommends --no-install-suggests \
    python3-build \
    python3-dev \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    ruby-dev \
    swig
```

To build and install everything under a private directory, run:

    make clean distclean

    make DESTDIR=~/obj install install-rubywrap install-pywrap

On Debian the environment variable `DEB_PYTHON_INSTALL_LAYOUT` needs to be set
to `deb` when installing the Python wrappers in order to create the correct
Python directory structure.
On Debian systems older than bookworm set
`PYTHON_SETUP_ARGS='--install-option "--install-layout=deb"'` instead.

To run tests with the built libraries and programs, several paths (relative to `$DESTDIR`) need to be added to variables `$LD_LIBRARY_PATH`, `$PATH` and `$PYTHONPATH`.
This can be done using [./scripts/env_use_destdir](./scripts/env_use_destdir):

    DESTDIR=~/obj ./scripts/env_use_destdir make test

Some tests require the reference policy to be installed (for example in `python/sepolgen`).

To install as the default system libraries and binaries
(overwriting any previously installed ones - dangerous!),
on x86_64, run:

    make LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install install-pywrap relabel

or on x86 (32-bit), run:

    make install install-pywrap relabel

This may render your system unusable if the upstream SELinux userspace
lacks library functions or other dependencies relied upon by your
distribution.  If it breaks, you get to keep both pieces.


## Setting CFLAGS

Setting CFLAGS during the make process will cause the omission of many defaults. While the project strives
to provide a reasonable set of default flags, custom CFLAGS could break the build, or have other undesired
changes on the build output. Thus, be very careful when setting CFLAGS. CFLAGS that are encouraged to be
set when overriding are:

- -fno-semantic-interposition for gcc or compilers that do not do this. clang does this by default. clang-10 and up
   will support passing this flag, but ignore it. Previous clang versions fail.

## Setting EXTRA_LD_FLAGS

Build with EXTRA_LD_FLAGS=--undefined-version to fix linking against
musl with llvm.

macOS
-----

To install libsepol on macOS (mainly for policy analysis):

    cd libsepol; make PREFIX=/usr/local install

This requires GNU coreutils:

    brew install coreutils
