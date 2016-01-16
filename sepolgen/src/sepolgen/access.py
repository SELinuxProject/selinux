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
Classes representing basic access.

SELinux - at the most basic level - represents access as
the 4-tuple subject (type or context), target (type or context),
object class, permission. The policy language elaborates this basic
access to faciliate more concise rules (e.g., allow rules can have multiple
source or target types - see refpolicy for more information).

This module has objects for representing the most basic access (AccessVector)
and sets of that access (AccessVectorSet). These objects are used in Madison
in a variety of ways, but they are the fundamental representation of access.
"""

from . import refpolicy
from . import util

from selinux import audit2why

def is_idparam(id):
    """Determine if an id is a paramater in the form $N, where N is
    an integer.

    Returns:
      True if the id is a paramater
      False if the id is not a paramater
    """
    if len(id) > 1 and id[0] == '$':
        try:
            int(id[1:])
        except ValueError:
            return False
        return True
    else:
        return False

class AccessVector(util.Comparison):
    """
    An access vector is the basic unit of access in SELinux.

    Access vectors are the most basic representation of access within
    SELinux. It represents the access a source type has to a target
    type in terms of an object class and a set of permissions.

    Access vectors are distinct from AVRules in that they can only
    store a single source type, target type, and object class. The
    simplicity of AccessVectors makes them useful for storing access
    in a form that is easy to search and compare.

    The source, target, and object are stored as string. No checking
    done to verify that the strings are valid SELinux identifiers.
    Identifiers in the form $N (where N is an integer) are reserved as
    interface parameters and are treated as wild cards in many
    circumstances.

    Properties:
     .src_type - The source type allowed access. [String or None]
     .tgt_type - The target type to which access is allowed. [String or None]
     .obj_class - The object class to which access is allowed. [String or None]
     .perms - The permissions allowed to the object class. [IdSet]
     .audit_msgs - The audit messages that generated this access vector [List of strings]
    """
    def __init__(self, init_list=None):
        if init_list:
            self.from_list(init_list)
        else:
            self.src_type = None
            self.tgt_type = None
            self.obj_class = None
            self.perms = refpolicy.IdSet()
            self.audit_msgs = []
            self.type = audit2why.TERULE
            self.data = []
        # when implementing __eq__ also __hash__ is needed on py2
        # if object is muttable __hash__ should be None
        self.__hash__ = None

        # The direction of the information flow represented by this
        # access vector - used for matching
        self.info_flow_dir = None

    def from_list(self, list):
        """Initialize an access vector from a list.

        Initialize an access vector from a list treating the list as
        positional arguments - i.e., 0 = src_type, 1 = tgt_type, etc.
        All of the list elements 3 and greater are treated as perms.
        For example, the list ['foo_t', 'bar_t', 'file', 'read', 'write']
        would create an access vector list with the source type 'foo_t',
        target type 'bar_t', object class 'file', and permissions 'read'
        and 'write'.

        This format is useful for very simple storage to strings or disc
        (see to_list) and for initializing access vectors.
        """
        if len(list) < 4:
            raise ValueError("List must contain at least four elements %s" % str(list))
        self.src_type = list[0]
        self.tgt_type = list[1]
        self.obj_class = list[2]
        self.perms = refpolicy.IdSet(list[3:])

    def to_list(self):
        """
        Convert an access vector to a list.

        Convert an access vector to a list treating the list as positional
        values. See from_list for more information on how an access vector
        is represented in a list.
        """
        l = [self.src_type, self.tgt_type, self.obj_class]
        l.extend(sorted(self.perms))
        return l

    def __str__(self):
        return self.to_string()

    def to_string(self):
        return "allow %s %s:%s %s;" % (self.src_type, self.tgt_type,
                                        self.obj_class, self.perms.to_space_str())

    def _compare(self, other, method):
        try:
            x = list(self.perms)
            a = (self.src_type, self.tgt_type, self.obj_class, x)
            y = list(other.perms)
            x.sort()
            y.sort()
            b = (other.src_type, other.tgt_type, other.obj_class, y)
            return method(a, b)
        except (AttributeError, TypeError):
            # trying to compare to foreign type
            return NotImplemented


def avrule_to_access_vectors(avrule):
    """Convert an avrule into a list of access vectors.

    AccessVectors and AVRules are similary, but differ in that
    an AVRule can more than one source type, target type, and
    object class. This function expands a single avrule into a
    list of one or more AccessVectors representing the access
    defined in the AVRule.

    
    """
    if isinstance(avrule, AccessVector):
        return [avrule]
    a = []
    for src_type in avrule.src_types:
        for tgt_type in avrule.tgt_types:
            for obj_class in avrule.obj_classes:
                access = AccessVector()
                access.src_type = src_type
                access.tgt_type = tgt_type
                access.obj_class = obj_class
                access.perms = avrule.perms.copy()
                a.append(access)
    return a

class AccessVectorSet:
    """A non-overlapping set of access vectors.

    An AccessVectorSet is designed to store one or more access vectors
    that are non-overlapping. Access can be added to the set
    incrementally and access vectors will be added or merged as
    necessary.  For example, adding the following access vectors using
    add_av:
       allow $1 etc_t : read;
       allow $1 etc_t : write;
       allow $1 var_log_t : read;
    Would result in an access vector set with the access vectors:
       allow $1 etc_t : { read write};
       allow $1 var_log_t : read;
    """
    def __init__(self):
        """Initialize an access vector set.
        """
        self.src = {}
        # The information flow direction of this access vector
        # set - see objectmodel.py for more information. This
        # stored here to speed up searching - see matching.py.
        self.info_dir = None

    def __iter__(self):
        """Iterate over all of the unique access vectors in the set."""
        for tgts in self.src.values():
            for objs in tgts.values():
                for av in objs.values():
                    yield av

    def __len__(self):
        """Return the number of unique access vectors in the set.

        Because of the inernal representation of the access vector set,
        __len__ is not a constant time operation. Worst case is O(N)
        where N is the number of unique access vectors, but the common
        case is probably better.
        """
        l = 0
        for tgts in self.src.values():
            for objs in tgts.values():
               l += len(objs)
        return l

    def to_list(self):
        """Return the unique access vectors in the set as a list.

        The format of the returned list is a set of nested lists,
        each access vector represented by a list. This format is
        designed to be simply  serializable to a file.

        For example, consider an access vector set with the following
        access vectors:
          allow $1 user_t : file read;
          allow $1 etc_t : file { read write};
        to_list would return the following:
          [[$1, user_t, file, read]
           [$1, etc_t, file, read, write]]

        See AccessVector.to_list for more information.
        """
        l = []
        for av in self:
            l.append(av.to_list())

        return l

    def from_list(self, l):
        """Add access vectors stored in a list.

        See to list for more information on the list format that this
        method accepts.

        This will add all of the access from the list. Any existing
        access vectors in the set will be retained.
        """
        for av in l:
            self.add_av(AccessVector(av))

    def add(self, src_type, tgt_type, obj_class, perms, audit_msg=None, avc_type=audit2why.TERULE, data=[]):
        """Add an access vector to the set.
        """
        tgt = self.src.setdefault(src_type, { })
        cls = tgt.setdefault(tgt_type, { })
        
        if (obj_class, avc_type) in cls:
            access = cls[obj_class, avc_type]
        else:
            access = AccessVector()
            access.src_type = src_type
            access.tgt_type = tgt_type
            access.obj_class = obj_class
            access.data = data
            access.type = avc_type
            cls[obj_class, avc_type] = access

        access.perms.update(perms)
        if audit_msg:
            access.audit_msgs.append(audit_msg)

    def add_av(self, av, audit_msg=None):
        """Add an access vector to the set."""
        self.add(av.src_type, av.tgt_type, av.obj_class, av.perms)


def avs_extract_types(avs):
    types = refpolicy.IdSet()
    for av in avs:
        types.add(av.src_type)
        types.add(av.tgt_type)
        
    return types

def avs_extract_obj_perms(avs):
    perms = { }
    for av in avs:
        if av.obj_class in perms:
            s = perms[av.obj_class]
        else:
            s = refpolicy.IdSet()
            perms[av.obj_class] = s
        s.update(av.perms)
    return perms

class RoleTypeSet:
    """A non-overlapping set of role type statements.

    This clas allows the incremental addition of role type statements and
    maintains a non-overlapping list of statements.
    """
    def __init__(self):
        """Initialize an access vector set."""
        self.role_types = {}

    def __iter__(self):
        """Iterate over all of the unique role allows statements in the set."""
        for role_type in self.role_types.values():
            yield role_type

    def __len__(self):
        """Return the unique number of role allow statements."""
        return len(self.role_types.keys())

    def add(self, role, type):
        if role in self.role_types:
            role_type = self.role_types[role]
        else:
            role_type = refpolicy.RoleType()
            role_type.role = role
            self.role_types[role] = role_type

        role_type.types.add(type)
