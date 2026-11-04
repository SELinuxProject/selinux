#!/usr/bin/python3

# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>
from setuptools import setup

setup(
    name="sepolicy",
    version="3.12-rc1",
    description="Python SELinux Policy Analyses bindings",
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
