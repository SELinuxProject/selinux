#!/usr/bin/env python

import sys
from setuptools import Extension, setup

PY_MAJOR_VERSION = sys.version_info[0]

if PY_MAJOR_VERSION >= 3:
    audit2why_map = "audit2why-py3.map"
    description = "SELinux python 3 bindings"
else:
    audit2why_map = "audit2why-py2.map"
    description = "SELinux python 2 bindings"

setup(
    name="selinux",
    version="3.10",
    description=description,
    author="SELinux Project",
    author_email="selinux@vger.kernel.org",
    ext_modules=[
        Extension('selinux._selinux',
                  sources=['selinuxswig_python.i'],
                  include_dirs=['../include'],
                  library_dirs=['.'],
                  libraries=['selinux']),
        Extension('selinux.audit2why',
                  sources=['audit2why.c'],
                  include_dirs=['../include'],
                  library_dirs=['.'],
                  libraries=['selinux'],
                  extra_link_args=['-l:libsepol.a', "-Wl,--version-script={}".format(audit2why_map])
    ],
)
