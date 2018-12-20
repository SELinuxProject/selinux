# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os
import re

# Select the correct location for the development files based on a
# path variable (optionally read from a configuration file)
class PathChooser(object):
    def __init__(self, pathname):
        self.config = dict()
        if not os.path.exists(pathname):
            self.config_pathname = "(defaults)"
            self.config["SELINUX_DEVEL_PATH"] = "/usr/share/selinux/default:/usr/share/selinux/mls:/usr/share/selinux/devel"
            return
        self.config_pathname = pathname
        ignore = re.compile(r"^\s*(?:#.+)?$")
        consider = re.compile(r"^\s*(\w+)\s*=\s*(.+?)\s*$")
        with open(pathname, "r") as fd:
            for lineno, line in enumerate(fd):
                if ignore.match(line): continue
                mo = consider.match(line)
                if not mo:
                    raise ValueError("%s:%d: line is not in key = value format" % (pathname, lineno+1))
                self.config[mo.group(1)] = mo.group(2)

    # We're only exporting one useful function, so why not be a function
    def __call__(self, testfilename, pathset="SELINUX_DEVEL_PATH"):
        paths = self.config.get(pathset, None)
        if paths is None:
            raise ValueError("%s was not in %s" % (pathset, self.config_pathname))
        paths = paths.split(":")
        for p in paths:
            target = os.path.join(p, testfilename)
            if os.path.exists(target): return target
        return os.path.join(paths[0], testfilename)


"""
Various default settings, including file and directory locations.
"""

def data_dir():
    return "/var/lib/sepolgen"

def perm_map():
    return data_dir() + "/perm_map"

def interface_info():
    return data_dir() + "/interface_info"

def attribute_info():
    return data_dir() + "/attribute_info"

def refpolicy_makefile():
    chooser = PathChooser("/etc/selinux/sepolgen.conf")
    result = chooser("Makefile")
    if not os.path.exists(result):
        result = chooser("include/Makefile")
    return result

def headers():
    chooser = PathChooser("/etc/selinux/sepolgen.conf")
    return chooser("include")

