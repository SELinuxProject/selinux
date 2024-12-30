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

import string
import selinux

# OVERVIEW
#
# This file contains objects and functions used to represent the reference
# policy (including the headers, M4 macros, and policy language statements).
#
# This representation is very different from the semantic representation
# used in libsepol. Instead, it is a more typical abstract representation
# used by the first stage of compilers. It is basically a parse tree.
#
# This choice is intentional as it allows us to handle the unprocessed
# M4 statements - including the $1 style arguments - and to more easily generate
# the data structures that we need for policy generation.
#

# Constants for referring to fields
SRC_TYPE  = 0
TGT_TYPE  = 1
OBJ_CLASS = 2
PERMS     = 3
ROLE      = 4
DEST_TYPE = 5

# String representations of the above constants
field_to_str = ["source", "target", "object", "permission", "role", "destination" ]
str_to_field = { "source" : SRC_TYPE, "target" : TGT_TYPE, "object" : OBJ_CLASS,
                "permission" : PERMS, "role" : ROLE, "destination" : DEST_TYPE }

# Base Classes

class PolicyBase:
    def __init__(self, parent=None):
        self.parent = None
        self.comment = None
        self.gen_cil = False

class Node(PolicyBase):
    """Base class objects produced from parsing the reference policy.

    The Node class is used as the base class for any non-leaf
    object produced by parsing the reference policy. This object
    should contain a reference to its parent (or None for a top-level
    object) and 0 or more children.

    The general idea here is to have a very simple tree structure. Children
    are not separated out by type. Instead the tree structure represents
    fairly closely the real structure of the policy statements.

    The object should be iterable - by default over all children but
    subclasses are free to provide additional iterators over a subset
    of their childre (see Interface for example).
    """

    def __init__(self, parent=None):
        PolicyBase.__init__(self, parent)
        self.children = []

    def __iter__(self):
        return iter(self.children)

    # Not all of the iterators will return something on all Nodes, but
    # they won't explode either. Putting them here is just easier.

    # Top level nodes

    def nodes(self):
        return filter(lambda x: isinstance(x, Node), walktree(self))

    def modules(self):
        return filter(lambda x: isinstance(x, Module), walktree(self))

    def interfaces(self):
        return filter(lambda x: isinstance(x, Interface), walktree(self))

    def templates(self):
        return filter(lambda x: isinstance(x, Template), walktree(self))

    def support_macros(self):
        return filter(lambda x: isinstance(x, SupportMacros), walktree(self))

    # Common policy statements

    def module_declarations(self):
        return filter(lambda x: isinstance(x, ModuleDeclaration), walktree(self))

    def interface_calls(self):
        return filter(lambda x: isinstance(x, InterfaceCall), walktree(self))

    def avrules(self):
        return filter(lambda x: isinstance(x, AVRule), walktree(self))

    def avextrules(self):
        return filter(lambda x: isinstance(x, AVExtRule), walktree(self))

    def typerules(self):
        return filter(lambda x: isinstance(x, TypeRule), walktree(self))

    def typebounds(self):
        return filter(lambda x: isinstance(x, TypeBound), walktree(self))

    def typeattributes(self):
        """Iterate over all of the TypeAttribute children of this Interface."""
        return filter(lambda x: isinstance(x, TypeAttribute), walktree(self))

    def roleattributes(self):
        """Iterate over all of the RoleAttribute children of this Interface."""
        return filter(lambda x: isinstance(x, RoleAttribute), walktree(self))

    def requires(self):
        return filter(lambda x: isinstance(x, Require), walktree(self))

    def roles(self):
        return filter(lambda x: isinstance(x, Role), walktree(self))

    def role_allows(self):
        return filter(lambda x: isinstance(x, RoleAllow), walktree(self))

    def role_types(self):
        return filter(lambda x: isinstance(x, RoleType), walktree(self))

    def __str__(self):
        if self.comment:
            return str(self.comment) + "\n" + self.to_string()
        else:
            return self.to_string()

    def __repr__(self):
        return "<%s(%s)>" % (self.__class__.__name__, self.to_string())

    def to_string(self):
        return ""

    def set_gen_cil(self, gen_cil):
        self.gen_cil = gen_cil

class Leaf(PolicyBase):
    def __init__(self, parent=None):
        PolicyBase.__init__(self, parent)

    def __str__(self):
        if self.comment:
            return str(self.comment) + "\n" + self.to_string()
        else:
            return self.to_string()

    def __repr__(self):
        return "<%s(%s)>" % (self.__class__.__name__, self.to_string())

    def to_string(self):
        return ""

    def set_gen_cil(self, gen_cil):
        self.gen_cil = gen_cil


# Utility functions

def walktree(node, depthfirst=True, showdepth=False, type=None):
    """Iterate over a Node and its Children.

    The walktree function iterates over a tree containing Nodes and
    leaf objects. The iteration can perform a depth first or a breadth
    first traversal of the tree (controlled by the depthfirst
    parameter. The passed in node will be returned.

    This function will only work correctly for trees - arbitrary graphs
    will likely cause infinite looping.
    """
    # We control depth first / versus breadth first by
    # how we pop items off of the node stack.
    if depthfirst:
        index = -1
    else:
        index = 0

    stack = [(node, 0)]
    while len(stack) > 0:
        cur, depth = stack.pop(index)
        if showdepth:
            yield cur, depth
        else:
            yield cur

        # If the node is not a Node instance it must
        # be a leaf - so no need to add it to the stack
        if isinstance(cur, Node):
            items = []
            i = len(cur.children) - 1
            while i >= 0:
                if type is None or isinstance(cur.children[i], type):
                    items.append((cur.children[i], depth + 1))
                i -= 1

            stack.extend(items)

def walknode(node, type=None):
    """Iterate over the direct children of a Node.

    The walktree function iterates over the children of a Node.
    Unlike walktree it does note return the passed in node or
    the children of any Node objects (that is, it does not go
    beyond the current level in the tree).
    """
    for x in node:
        if type is None or isinstance(x, type):
            yield x


def list_to_space_str(s, cont=('{', '}')):
    """Convert a set (or any sequence type) into a string representation
    formatted to match SELinux space separated list conventions.

    For example the list ['read', 'write'] would be converted into:
    '{ read write }'
    """
    l = len(s)
    str = ""
    if l < 1:
        raise ValueError("cannot convert 0 len set to string")
    str = " ".join(s)
    if l == 1:
        return str
    else:
        return cont[0] + " " + str + " " + cont[1]

def list_to_comma_str(s):
    l = len(s)
    if l < 1:
        raise ValueError("cannot convert 0 len set to comma string")

    return ", ".join(s)

# Basic SELinux types

class IdSet(set):
    def __init__(self, list=None):
        if list:
            set.__init__(self, list)
        else:
            set.__init__(self)
        self.compliment = False

    def to_space_str(self):
        return list_to_space_str(sorted(self))

    def to_comma_str(self):
        return list_to_comma_str(sorted(self))

class SecurityContext(Leaf):
    """An SELinux security context with optional MCS / MLS fields."""
    def __init__(self, context=None, parent=None):
        """Create a SecurityContext object, optionally from a string.

        Parameters:
           [context] - string representing a security context. Same format
              as a string passed to the from_string method.
        """
        Leaf.__init__(self, parent)
        self.user = ""
        self.role = ""
        self.type = ""
        self.level = None
        if context is not None:
            self.from_string(context)

    def from_string(self, context):
        """Parse a string representing a context into a SecurityContext.

        The string should be in the standard format - e.g.,
        'user:role:type:level'.

        Raises ValueError if the string is not parsable as a security context.
        """
        # try to translate the context string to raw form
        raw = selinux.selinux_trans_to_raw_context(context)
        if raw[0] == 0:
            context = raw[1]

        fields = context.split(":")
        if len(fields) < 3:
            raise ValueError("context string [%s] not in a valid format" % context)

        self.user = fields[0]
        self.role = fields[1]
        self.type = fields[2]
        if len(fields) > 3:
            # FUTURE - normalize level fields to allow more comparisons to succeed.
            self.level = ':'.join(fields[3:])
        else:
            self.level = None

    def __eq__(self, other):
        """Compare two SecurityContext objects - all fields must be exactly the
        the same for the comparison to work. It is possible for the level fields
        to be semantically the same yet syntactically different - in this case
        this function will return false.
        """
        return self.user == other.user and \
               self.role == other.role and \
               self.type == other.type and \
               self.level == other.level

    def to_string(self, default_level=None):
        """Return a string representing this security context.

        By default, the string will contain a MCS / MLS level
        potentially from the default which is passed in if none was
        set.

        Arguments:
           default_level - the default level to use if self.level is an
             empty string.

        Returns:
           A string representing the security context in the form
              'user:role:type:level'.
        """
        fields = [self.user, self.role, self.type]
        if self.level is None:
            if default_level is None:
                if selinux.is_selinux_mls_enabled() == 1:
                    fields.append("s0")
            else:
                fields.append(default_level)
        else:
            fields.append(self.level)
        return ":".join(fields)

class ObjectClass(Leaf):
    """SELinux object class and permissions.

    This class is a basic representation of an SELinux object
    class - it does not represent separate common permissions -
    just the union of the common and class specific permissions.
    It is meant to be convenient for policy generation.
    """
    def __init__(self, name="", parent=None):
        Leaf.__init__(self, parent)
        self.name = name
        self.perms = IdSet()

class XpermSet():
    """Extended permission set.

    This class represents one or more extended permissions
    represented by numeric values or ranges of values. The
    .complement attribute is used to specify all permission
    except those specified.

    Two xperm set can be merged using the .extend() method.
    """
    def __init__(self, complement=False):
        self.complement = complement
        self.ranges = []

    def __normalize_ranges(self):
        """Ensure that ranges are not overlapping.
        """
        self.ranges.sort()

        i = 0
        while i < len(self.ranges):
            while i + 1 < len(self.ranges):
                if self.ranges[i + 1][0] <= self.ranges[i][1] + 1:
                    self.ranges[i] = (self.ranges[i][0], max(self.ranges[i][1],
                                                             self.ranges[i + 1][1]))
                    del self.ranges[i + 1]
                else:
                    break
            i += 1

    def extend(self, s):
        """Add ranges from an xperm set
        """
        self.ranges.extend(s.ranges)
        self.__normalize_ranges()

    def add(self, minimum, maximum=None):
        """Add value of range of values to the xperm set.
        """
        if maximum is None:
            maximum = minimum
        self.ranges.append((minimum, maximum))
        self.__normalize_ranges()

    def to_string(self):
        if not self.ranges:
            return ""

        compl = "~ " if self.complement else ""

        # print single value without braces
        if len(self.ranges) == 1 and self.ranges[0][0] == self.ranges[0][1]:
            return compl + hex(self.ranges[0][0])

        vals = map(lambda x: hex(x[0]) if x[0] == x[1] else "%s-%s" % (hex(x[0]), hex(x[1]), ), self.ranges)

        return "%s{ %s }" % (compl, " ".join(vals))

    def to_string_cil(self):
        if not self.ranges:
            return ""

        compl = ("not (", ")") if self.complement else ("", "")

        vals = map(lambda x: hex(x[0]) if x[0] == x[1] else "(range %s %s)" % (hex(x[0]), hex(x[1]), ), self.ranges)

        return "(%s%s%s)" % (compl[0], " ".join(vals), compl[1])

# Basic statements

class TypeAttribute(Leaf):
    """SElinux typeattribute statement.

    This class represents a typeattribute statement.
    """
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.type = ""
        self.attributes = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = ""
            for a in self.attributes:
                s += "(typeattribute %s)\n" % a
                s += "(typeattributeset %s %s)\n" % (a, self.type)
            return s
        else:
            return "typeattribute %s %s;" % (self.type, self.attributes.to_comma_str())

class RoleAttribute(Leaf):
    """SElinux roleattribute statement.

    This class represents a roleattribute statement.
    """
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.role = ""
        self.roleattributes = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = ""
            for a in self.roleattributes:
                s += "(roleattribute %s)\n" % a
                s += "(roleattributeset %s %s)\n" % (a, self.type)
            return s
        else:
            return "roleattribute %s %s;" % (self.role, self.roleattributes.to_comma_str())


class Role(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.role = ""
        self.types = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = "(role %s)\n" % self.role
            for t in self.types:
                s += "(roletype %s %s)\n" % (self.role, t)
            return s
        else:
            s = ""
            for t in self.types:
                s += "role %s types %s;\n" % (self.role, t)
            return s

class Type(Leaf):
    def __init__(self, name="", parent=None):
        Leaf.__init__(self, parent)
        self.name = name
        self.attributes = IdSet()
        self.aliases = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = "(type %s)\n" % self.name
            for a in self.aliases:
                s += "(typealiasactual %s %s)\n" % (a, self.name)
            for a in self.attributes:
                s += "(typeattributeset %s %s)\n" % (a, self.name)
            return s
        else:
            s = "type %s" % self.name
            if len(self.aliases) > 0:
                s = s + "alias %s" % self.aliases.to_space_str()
            if len(self.attributes) > 0:
                s = s + ", %s" % self.attributes.to_comma_str()
            return s + ";"

class TypeAlias(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.type = ""
        self.aliases = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = ""
            for a in self.aliases:
                s += "(typealias %s)\n" % a
                s += "(typealiasactual %s %s)\n" % (a, self.type)
            return s
        else:
            return "typealias %s alias %s;" % (self.type, self.aliases.to_space_str())

class Attribute(Leaf):
    def __init__(self, name="", parent=None):
        Leaf.__init__(self, parent)
        self.name = name

    def to_string(self):
        if self.gen_cil:
            return "attribute %s;" % self.name
        else:
            return "(typeattribute %s)" % self.name

class Attribute_Role(Leaf):
    def __init__(self, name="", parent=None):
        Leaf.__init__(self, parent)
        self.name = name

    def to_string(self):
        if self.gen_cil:
            return "(roleattribute %s)" % self.name
        else:
            return "attribute_role %s;" % self.name


# Classes representing rules

class AVRule(Leaf):
    """SELinux access vector (AV) rule.

    The AVRule class represents all varieties of AV rules including
    allow, dontaudit, and auditallow (indicated by the flags self.ALLOW,
    self.DONTAUDIT, and self.AUDITALLOW respectively).

    The source and target types, object classes, and perms are all represented
    by sets containing strings. Sets are used to make it simple to add
    strings repeatedly while avoiding duplicates.

    No checking is done to make certain that the symbols are valid or
    consistent (e.g., perms that don't match the object classes). It is
    even possible to put invalid types like '$1' into the rules to allow
    storage of the reference policy interfaces.
    """
    ALLOW = 0
    DONTAUDIT = 1
    AUDITALLOW = 2
    NEVERALLOW = 3

    def __init__(self, av=None, parent=None):
        Leaf.__init__(self, parent)
        self.src_types = IdSet()
        self.tgt_types = IdSet()
        self.obj_classes = IdSet()
        self.perms = IdSet()
        self.rule_type = self.ALLOW
        if av:
            self.from_av(av)

    def __rule_type_str(self):
        if self.rule_type == self.ALLOW:
            return "allow"
        elif self.rule_type == self.DONTAUDIT:
            return "dontaudit"
        elif self.rule_type == self.AUDITALLOW:
            return "auditallow"
        elif self.rule_type == self.NEVERALLOW:
            return "neverallow"

    def from_av(self, av):
        """Add the access from an access vector to this allow
        rule.
        """
        self.src_types.add(av.src_type)
        if av.src_type == av.tgt_type:
            self.tgt_types.add("self")
        else:
            self.tgt_types.add(av.tgt_type)
        self.obj_classes.add(av.obj_class)
        self.perms.update(av.perms)

    def to_string(self):
        """Return a string representation of the rule
        that is a valid policy language representation (assuming
        that the types, object class, etc. are valid).
        """
        if self.gen_cil:
            s = ""
            for src in self.src_types:
                for tgt in self.tgt_types:
                    for obj in self.obj_classes:
                        s += "(%s %s %s (%s (%s)))" % (self.__rule_type_str(),
                                                       src, tgt, obj,
                                                       " ".join(self.perms))
            return s
        else:
            return "%s %s %s:%s %s;" % (self.__rule_type_str(),
                                        self.src_types.to_space_str(),
                                        self.tgt_types.to_space_str(),
                                        self.obj_classes.to_space_str(),
                                        self.perms.to_space_str())

class AVExtRule(Leaf):
    """Extended permission access vector rule.

    The AVExtRule class represents allowxperm, dontauditxperm,
    auditallowxperm, and neverallowxperm rules.

    The source and target types, and object classes are represented
    by sets containing strings. The operation is a single string,
    e.g. 'ioctl'. Extended permissions are represented by an XpermSet.
    """
    ALLOWXPERM = 0
    DONTAUDITXPERM = 1
    AUDITALLOWXPERM = 2
    NEVERALLOWXPERM = 3

    def __init__(self, av=None, op=None, parent=None):
        Leaf.__init__(self, parent)
        self.src_types = IdSet()
        self.tgt_types = IdSet()
        self.obj_classes = IdSet()
        self.rule_type = self.ALLOWXPERM
        self.xperms = XpermSet()
        self.operation = op
        if av:
            self.from_av(av, op)

    def __rule_type_str(self):
        if self.rule_type == self.ALLOWXPERM:
            return "allowxperm"
        elif self.rule_type == self.DONTAUDITXPERM:
            return "dontauditxperm"
        elif self.rule_type == self.AUDITALLOWXPERM:
            return "auditallowxperm"
        elif self.rule_type == self.NEVERALLOWXPERM:
            return "neverallowxperm"

    def __rule_type_str_cil(self):
        if self.rule_type == self.ALLOWXPERM:
            return "allowx"
        elif self.rule_type == self.DONTAUDITXPERM:
            return "dontauditx"
        elif self.rule_type == self.AUDITALLOWXPERM:
            return "auditallowx"
        elif self.rule_type == self.NEVERALLOWXPERM:
            return "neverallowx"

    def from_av(self, av, op):
        self.src_types.add(av.src_type)
        if av.src_type == av.tgt_type:
            self.tgt_types.add("self")
        else:
            self.tgt_types.add(av.tgt_type)
        self.obj_classes.add(av.obj_class)
        self.operation = op
        self.xperms = av.xperms[op]

    def to_string(self):
        """Return a string representation of the rule that is
        a valid policy language representation (assuming that
        the types, object class, etc. are valid).
        """
        if self.gen_cil:
            s = ""
            for src in self.src_types:
                for tgt in self.tgt_types:
                    for obj in self.obj_classes:
                        s += "(%s %s %s (%s %s %s))" % (self.__rule_type_str_cil(),
                                                        src, tgt,
                                                        self.operation,
                                                        obj,
                                                        self.xperms.to_string_cil())
            return s
        else:
            return "%s %s %s:%s %s %s;" % (self.__rule_type_str(),
                                           self.src_types.to_space_str(),
                                           self.tgt_types.to_space_str(),
                                           self.obj_classes.to_space_str(),
                                           self.operation,
                                           self.xperms.to_string())


class TypeRule(Leaf):
    """SELinux type rules.

    This class is very similar to the AVRule class, but is for representing
    the type rules (type_trans, type_change, and type_member). The major
    difference is the lack of perms and only and sing destination type.
    """
    TYPE_TRANSITION = 0
    TYPE_CHANGE = 1
    TYPE_MEMBER = 2

    # NB. Filename type transitions are not generated by audit2allow.
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.src_types = IdSet()
        self.tgt_types = IdSet()
        self.obj_classes = IdSet()
        self.dest_type = ""
        self.rule_type = self.TYPE_TRANSITION

    def __rule_type_str(self):
        if self.rule_type == self.TYPE_TRANSITION:
            return "type_transition"
        elif self.rule_type == self.TYPE_CHANGE:
            return "type_change"
        else:
            return "type_member"

    def __rule_type_str_cil(self):
        if self.rule_type == self.TYPE_TRANSITION:
            return "typetransition"
        elif self.rule_type == self.TYPE_CHANGE:
            return "typechange"
        else:
            return "typemember"

    def to_string(self):
        if self.gen_cil:
            return "(%s %s %s %s %s)" % (self.__rule_type_str_cil(),
                                         self.src_types.to_space_str(),
                                         self.tgt_types.to_space_str(),
                                         self.obj_classes.to_space_str(),
                                         self.dest_type)
        else:
            return "%s %s %s:%s %s;" % (self.__rule_type_str(),
                                        self.src_types.to_space_str(),
                                        self.tgt_types.to_space_str(),
                                        self.obj_classes.to_space_str(),
                                        self.dest_type)

class TypeBound(Leaf):
    """SElinux typebound statement.

    This class represents a typebound statement.
    """
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.type = ""
        self.tgt_types = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = ""
            for t in self.tgt_types:
                s += "(typebounds %s %s)" % (self.type, t)
            return s
        else:
            return "typebounds %s %s;" % (self.type, self.tgt_types.to_comma_str())

class RoleAllow(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.src_roles = IdSet()
        self.tgt_roles = IdSet()

    def to_string(self):
        if self.gen_cil:
            s = ""
            for src in self.src_roles:
                for tgt in self.tgt_roles:
                    s += "(roleallow %s %s)" % (src, tgt)
            return s
        else:
            return "allow %s %s;" % (self.src_roles.to_comma_str(),
                                     self.tgt_roles.to_comma_str())

class RoleType(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.role = ""
        self.types = IdSet()

    def to_string(self):
        s = ""
        for t in self.types:
            if self.gen_cil:
                s += "(roletype %s %s)\n" % (self.role, t)
            else:
                s += "role %s types %s;\n" % (self.role, t)
        return s

class ModuleDeclaration(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.name = ""
        self.version = ""
        self.refpolicy = False

    def to_string(self):
        if self.gen_cil:
            return ""
        else:
            if self.refpolicy:
                return "policy_module(%s, %s)" % (self.name, self.version)
            else:
                return "module %s %s;" % (self.name, self.version)

class Conditional(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)
        self.cond_expr = []

    def to_string(self):
        return "[If %s]" % list_to_space_str(self.cond_expr, cont=("", ""))

class Bool(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.name = ""
        self.state = False

    def to_string(self):
        s = "bool %s " % self.name
        if s.state:
            return s + "true"
        else:
            return s + "false"

class InitialSid(Leaf):
    def __init(self, parent=None):
        Leaf.__init__(self, parent)
        self.name = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(sid %s %s)" % (self.name, str(self.context))
        else:
            return "sid %s %s" % (self.name, str(self.context))

class GenfsCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.filesystem = ""
        self.path = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(genfscon %s %s %s)" % (self.filesystem, self.path, str(self.context))
        else:
            return "genfscon %s %s %s" % (self.filesystem, self.path, str(self.context))

class FilesystemUse(Leaf):
    XATTR = 1
    TRANS = 2
    TASK = 3
    
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.type = self.XATTR
        self.filesystem = ""
        self.context = None

    def to_string(self):
        s = ""
        if self.gen_cil:
            if self.type == self.XATTR:
                s = "fsuse xattr "
            elif self.type == self.TRANS:
                s = "fsuse trans "
            elif self.type == self.TASK:
                s = "fsuse task "

            return "(%s %s %s)" % (s, self.filesystem, str(self.context))
        else:
            if self.type == self.XATTR:
                s = "fs_use_xattr "
            elif self.type == self.TRANS:
                s = "fs_use_trans "
            elif self.type == self.TASK:
                s = "fs_use_task "

            return "%s %s %s;" % (s, self.filesystem, str(self.context))

class PortCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.port_type = ""
        self.port_number = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(portcon %s %s %s)" % (self.port_type, self.port_number, str(self.context))
        else:
            return "portcon %s %s %s" % (self.port_type, self.port_number, str(self.context))

class NodeCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.start = ""
        self.end = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(nodecon %s %s %s)" % (self.start, self.end, str(self.context))
        else:
            return "nodecon %s %s %s" % (self.start, self.end, str(self.context))

class NetifCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.interface = ""
        self.interface_context = None
        self.packet_context = None

    def to_string(self):
        if self.gen_cil:
            return "(netifcon %s %s %s)" % (self.interface, str(self.interface_context),
                                            str(self.packet_context))
        else:
            return "netifcon %s %s %s" % (self.interface, str(self.interface_context),
                                          str(self.packet_context))

class PirqCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.pirq_number = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(pirqcon %s %s)" % (self.pirq_number, str(self.context))
        else:
            return "pirqcon %s %s" % (self.pirq_number, str(self.context))

class IomemCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.device_mem = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(iomemcon %s %s)" % (self.device_mem, str(self.context))
        else:
            return "iomemcon %s %s" % (self.device_mem, str(self.context))

class IoportCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.ioport = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(ioportcon %s %s)" % (self.ioport, str(self.context))
        else:
            return "ioportcon %s %s" % (self.ioport, str(self.context))

class PciDeviceCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.device = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(pcidevicecon %s %s)" % (self.device, str(self.context))
        else:
            return "pcidevicecon %s %s" % (self.device, str(self.context))

class DeviceTreeCon(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.path = ""
        self.context = None

    def to_string(self):
        if self.gen_cil:
            return "(devicetreecon %s %s)" % (self.path, str(self.context))
        else:
            return "devicetreecon %s %s" % (self.path, str(self.context))

# Reference policy specific types

def print_tree(head):
    for node, depth in walktree(head, showdepth=True):
        s = ""
        for i in range(depth):
            s = s + "\t"
        print(s + str(node))


class Headers(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)

    def to_string(self):
        return "[Headers]"


class Module(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)

    def to_string(self):
        return ""

class Interface(Node):
    """A reference policy interface definition.

    This class represents a reference policy interface definition.
    """
    def __init__(self, name="", parent=None):
        Node.__init__(self, parent)
        self.name = name

    def to_string(self):
        return "[Interface name: %s]" % self.name

class TunablePolicy(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)
        self.cond_expr = []

    def to_string(self):
        return "[Tunable Policy %s]" % list_to_space_str(self.cond_expr, cont=("", ""))

class Template(Node):
    def __init__(self, name="", parent=None):
        Node.__init__(self, parent)
        self.name = name

    def to_string(self):
        return "[Template name: %s]" % self.name

class IfDef(Node):
    def __init__(self, name="", parent=None):
        Node.__init__(self, parent)
        self.name = name

    def to_string(self):
        return "[Ifdef name: %s]" % self.name

class IfElse(Node):
    def __init__(self, name="", parent=None):
        Node.__init__(self, parent)
        self.name = name

    def to_string(self):
        return "[Ifelse name: %s]" % self.name

class InterfaceCall(Leaf):
    def __init__(self, ifname="", parent=None):
        Leaf.__init__(self, parent)
        self.ifname = ifname
        self.args = []
        self.comments = []

    def matches(self, other):
        if self.ifname != other.ifname:
            return False
        if len(self.args) != len(other.args):
            return False
        for a,b in zip(self.args, other.args):
            if a != b:
                return False
        return True

    def to_string(self):
        s = "%s(" % self.ifname
        i = 0
        for a in self.args:
            if isinstance(a, list):
                str = list_to_space_str(a)
            else:
                str = a
                
            if i != 0:
                s = s + ", %s" % str
            else:
                s = s + str
            i += 1
        return s + ")"

class OptionalPolicy(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)

    def to_string(self):
        return "[Optional Policy]"

class SupportMacros(Node):
    def __init__(self, parent=None):
        Node.__init__(self, parent)
        self.map = None

    def to_string(self):
        return "[Support Macros]"

    def __expand_perm(self, perm):
        # Recursive expansion - the assumption is that these
        # are ordered correctly so that no macro is used before
        # it is defined
        s = set()
        if perm in self.map:
            for p in self.by_name(perm):
                s.update(self.__expand_perm(p))
        else:
            s.add(perm)
        return s

    def __gen_map(self):
        self.map = {}
        for x in self:
            exp_perms = set()
            for perm in x.perms:
                exp_perms.update(self.__expand_perm(perm))
            self.map[x.name] = exp_perms

    def by_name(self, name):
        if not self.map:
            self.__gen_map()
        return self.map[name]

    def has_key(self, name):
        if not self.map:
            self.__gen_map()
        return name in self.map

class Require(Leaf):
    def __init__(self, parent=None):
        Leaf.__init__(self, parent)
        self.types = IdSet()
        self.obj_classes = { }
        self.roles = IdSet()
        self.data = IdSet()
        self.users = IdSet()

    def add_obj_class(self, obj_class, perms):
        p = self.obj_classes.setdefault(obj_class, IdSet())
        p.update(perms)


    def to_string(self):
        s = []
        if self.gen_cil:
            # Can't require classes, perms, booleans, users
            for type in self.types:
                s.append("(typeattributeset cil_gen_require %s)" % type)
            for role in self.roles:
                s.append("(roleattributeset cil_gen_require %s)" % role)

            return "\n".join(s)
        else:
            s.append("require {")
            for type in self.types:
                s.append("\ttype %s;" % type)
            for obj_class, perms in self.obj_classes.items():
                s.append("\tclass %s %s;" % (obj_class, perms.to_space_str()))
            for role in self.roles:
                s.append("\trole %s;" % role)
            for bool in self.data:
                s.append("\tbool %s;" % bool)
            for user in self.users:
                s.append("\tuser %s;" % user)
            s.append("}")

            # Handle empty requires
            if len(s) == 2:
                return ""

            return "\n".join(s)

class ObjPermSet:
    def __init__(self, name):
        self.name = name
        self.perms = set()

    def to_string(self):
        return "define(`%s', `%s')" % (self.name, self.perms.to_space_str())

class ClassMap:
    def __init__(self, obj_class, perms):
        self.obj_class = obj_class
        self.perms = perms

    def to_string(self):
        return self.obj_class + ": " + self.perms

class Comment:
    def __init__(self, l=None):
        if l:
            self.lines = l
        else:
            self.lines = []
        self.gen_cil = False

    def to_string(self):
        # If there are no lines, treat this as a spacer between
        # policy statements and return a new line.
        if len(self.lines) == 0:
            return ""
        else:
            out = []
            for line in self.lines:
                if self.gen_cil:
                    out.append(";" + line)
                else:
                    out.append("#" + line)
            return "\n".join(out)

    def merge(self, other):
        if len(other.lines):
            for line in other.lines:
                if line != "":
                    self.lines.append(line)

    def __str__(self):
        return self.to_string()

    def set_gen_cil(self, gen_cil):
        self.gen_cil = gen_cil
