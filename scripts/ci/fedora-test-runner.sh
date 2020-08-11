#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -ev

#
# We expect this to be set in the environment, but if it's not, most selinux projects
# just have the same name as upstream, so choose that.
#
export SELINUX_DIR="${SELINUX_DIR:-/root/selinux}"

# CI Debug output if things go squirrely.
getenforce
id -Z
nproc
pwd

# Turn off enforcing for the setup to prevent any weirdness from breaking
# the CI.
setenforce 0

dnf clean all -y
dnf install -y \
    --allowerasing \
    --skip-broken \
    git \
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
    pcre-devel \
    xmlto \
    python3-devel \
    ruby-devel \
    swig \
    perl-Test \
    perl-Test-Harness \
    perl-Test-Simple \
    selinux-policy-devel \
    gcc \
    libselinux-devel \
    net-tools \
    netlabel_tools \
    iptables \
    lksctp-tools-devel \
    attr \
    libbpf-devel \
    keyutils-libs-devel \
    kernel-devel \
    quota \
    xfsprogs-devel \
    libuuid-devel \
    kernel-devel-"$(uname -r)" \
    kernel-modules-"$(uname -r)"

#
# Move to selinux code and build
#
cd "$SELINUX_DIR"

# Show HEAD commit for sanity checking
git log --oneline -1

#
# Build and replace userspace components
#
make -j"$(nproc)" LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install
make -j"$(nproc)" LIBDIR=/usr/lib64 SHLIBDIR=/lib64 install-pywrap
make -j"$(nproc)" LIBDIR=/usr/lib64 SHLIBDIR=/lib64 relabel

#
# Get the selinux testsuite, but don't clone it in selinux git directory, move to $HOME
# first.
#
cd "$HOME"
git clone --depth=1 https://github.com/SELinuxProject/selinux-testsuite.git
cd selinux-testsuite

# The testsuite must be run in enforcing mode
setenforce 1

#
# Run the test suite
#
make test
