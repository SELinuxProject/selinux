#!/usr/bin/env python

# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>
import os
from distutils.core import setup, Extension
policy = Extension("sepolicy._policy",
                   libraries=["apol", "qpol"],
                   sources=["policy.c", "info.c", "search.c"]
                   )

setup(name="sepolicy", version="1.1", description="Python SELinux Policy Analyses bindings", author="Daniel Walsh", author_email="dwalsh@redhat.com", ext_modules=[policy], packages=["sepolicy", "sepolicy.templates", "sepolicy.help"], package_data={'sepolicy': ['*.glade'], 'sepolicy.help': ['*.txt', '*.png']})
