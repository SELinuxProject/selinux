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

"""
This module provides knowledge object classes and permissions. It should
be used to keep this knowledge from leaking into the more generic parts of
the policy generation.
"""

# Objects that can be implicitly typed - these objects do
# not _have_ to be implicitly typed (e.g., sockets can be
# explicitly labeled), but they often are.
#
# File is in this list for /proc/self
#
# This list is useful when dealing with rules that have a
# type (or param) used as both a subject and object. For
# example:
#
#   allow httpd_t httpd_t : socket read;
#
# This rule makes sense because the socket was (presumably) created
# by a process with the type httpd_t.
implicitly_typed_objects = ["socket", "fd", "process", "file", "lnk_file", "fifo_file",
                            "dbus", "capability", "unix_stream_socket"]

#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#
#Information Flow
#
# All of the permissions in SELinux can be described in terms of
# information flow. For example, a read of a file is a flow of
# information from that file to the process reading. Viewing
# permissions in these terms can be used to model a variety of
# security properties.
#
# Here we have some infrastructure for understanding permissions
# in terms of information flow
#
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# Information flow deals with information either flowing from a subject
# to and object ("write") or to a subject from an object ("read"). Read
# or write is described from the subject point-of-view. It is also possible
# for a permission to represent both a read and write (though the flow is
# typical asymettric in terms of bandwidth). It is also possible for
# permission to not flow information (meaning that the result is pure
# side-effect).
#
# The following constants are for representing the directionality
# of information flow.
FLOW_NONE  = 0
FLOW_READ  = 1
FLOW_WRITE = 2
FLOW_BOTH  = FLOW_READ | FLOW_WRITE

# These are used by the parser and for nice display of the directions
str_to_dir = { "n" : FLOW_NONE, "r" : FLOW_READ, "w" : FLOW_WRITE, "b" : FLOW_BOTH }
dir_to_str = { FLOW_NONE : "n", FLOW_READ : "r", FLOW_WRITE : "w", FLOW_BOTH : "b" }

class PermMap:
    """A mapping between a permission and its information flow properties.

    PermMap represents the information flow properties of a single permission
    including the direction (read, write, etc.) and an abstract representation
    of the bandwidth of the flow (weight).
    """
    def __init__(self, perm, dir, weight):
        self.perm = perm
        self.dir = dir
        self.weight = weight

    def __repr__(self):
        return "<sepolgen.objectmodel.PermMap %s %s %d>" % (self.perm,
                                                           dir_to_str[self.dir],
                                                           self.weight)

class PermMappings:
    """The information flow properties of a set of object classes and permissions.

    PermMappings maps one or more classes and permissions to their PermMap objects
    describing their information flow characteristics.
    """
    def __init__(self):
        self.classes = { }
        self.default_weight = 5
        self.default_dir = FLOW_BOTH

    def from_file(self, fd):
        """Read the permission mappings from a file. This reads the format used
        by Apol in the setools suite.
        """
        # This parsing is deliberately picky and bails at the least error. It
        # is assumed that the permission map file will be shipped as part
        # of sepolgen and not user modified, so this is a reasonable design
        # choice. If user supplied permission mappings are needed the parser
        # should be made a little more robust and give better error messages.
        cur = None
        for line in fd:
            fields = line.split()
            if len(fields) == 0 or len(fields) == 1 or fields[0] == "#":
                continue
            if fields[0] == "class":
                c = fields[1]
                if c in self.classes:
                    raise ValueError("duplicate class in perm map")
                self.classes[c] = { }
                cur = self.classes[c]
            else:
                if len(fields) != 3:
                    raise ValueError("error in object class permissions")
                if cur is None:
                    raise ValueError("permission outside of class")
                pm = PermMap(fields[0], str_to_dir[fields[1]], int(fields[2]))
                cur[pm.perm] = pm

    def get(self, obj, perm):
        """Get the permission map for the object permission.

        Returns:
          PermMap representing the permission
        Raises:
          KeyError if the object or permission is not defined
        """
        return self.classes[obj][perm]

    def getdefault(self, obj, perm):
        """Get the permission map for the object permission or a default.

        getdefault is the same as get except that a default PermMap is
        returned if the object class or permission is not defined. The
        default is FLOW_BOTH with a weight of 5.
        """
        try:
            pm = self.classes[obj][perm]
        except KeyError:
            return PermMap(perm, self.default_dir, self.default_weight)
        return pm

    def getdefault_direction(self, obj, perms):
        dir = FLOW_NONE
        for perm in perms:
            pm = self.getdefault(obj, perm)
            dir = dir | pm.dir
        return dir

    def getdefault_distance(self, obj, perms):
        total = 0
        for perm in perms:
            pm = self.getdefault(obj, perm)
            total += pm.weight

        return total



