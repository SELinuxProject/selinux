#!/usr/bin/python3

# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>
from setuptools import setup

setup(
    name="sepolicy",
    version="3.10-rc1",
    description="Python SELinux Policy Analyses bindings",
    author="Daniel Walsh",
    author_email="dwalsh@redhat.com",
    packages=[
        "sepolicy",
        "sepolicy.templates",
        "sepolicy.help"
    ],
    package_data={
        'sepolicy': ['*.glade'],
        'sepolicy.help': ['*.txt', '*.png']
    }
)
