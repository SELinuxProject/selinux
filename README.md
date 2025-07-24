SELinux Userspace
=================

![SELinux logo](https://github.com/SELinuxProject.png)
[![Run Tests](https://github.com/SELinuxProject/selinux/actions/workflows/run_tests.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/run_tests.yml)
[![Run SELinux testsuite in Testing Farm](https://github.com/SELinuxProject/selinux/actions/workflows/tf_testsuite.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/tf_testsuite.yml)
[![OSS-Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/selinux.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#selinux)
[![CIFuzz Status](https://github.com/SELinuxProject/selinux/actions/workflows/cifuzz.yml/badge.svg)](https://github.com/SELinuxProject/selinux/actions/workflows/cifuzz.yml)

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

Installation
------------

SELinux libraries and tools are packaged in several Linux distributions:

* Alpine Linux (https://pkgs.alpinelinux.org/package/edge/testing/x86/policycoreutils)
* Arch Linux User Repository (https://aur.archlinux.org/packages/policycoreutils/)
* Buildroot (https://git.buildroot.net/buildroot/tree/package/policycoreutils)
* Debian and Ubuntu (https://packages.debian.org/sid/policycoreutils)
* Gentoo (https://packages.gentoo.org/packages/sys-apps/policycoreutils)
* RHEL and Fedora (https://src.fedoraproject.org/rpms/policycoreutils)
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


macOS
-----

To install libsepol on macOS (mainly for policy analysis):

    cd libsepol; make PREFIX=/usr/local install

This requires GNU coreutils:

    brew install coreutils
