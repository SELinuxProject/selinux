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
Classes and functions for the output of reference policy modules.

This module takes a refpolicy.Module object and formats it for
output using the ModuleWriter object. By separating the output
in this way the other parts of Madison can focus solely on
generating policy. This keeps the semantic / syntactic issues
cleanly separated from the formatting issues.
"""

from . import refpolicy
from . import util

if util.PY3:
    from .util import cmp


class ModuleWriter:
    def __init__(self):
        self.fd = None
        self.module = None
        self.sort = True
        self.requires = True
        self.gen_cil = False

    def write(self, module, fd):
        self.module = module

        if self.sort:
            sort_filter(self.module)

        # FIXME - make this handle nesting
        for node, depth in refpolicy.walktree(self.module, showdepth=True):
            node.set_gen_cil(self.gen_cil)
            fd.write("%s\n" % str(node))

    def set_gen_cil(self, gen_cil):
        self.gen_cil = gen_cil

# Helper functions for sort_filter - this is all done old school
# C style rather than with polymorphic methods because this sorting
# is specific to output. It is not necessarily the comparison you
# want generally.

# Compare two IdSets - we could probably do something clever
# with different here, but this works.
def id_set_cmp(x, y):
    xl = util.set_to_list(x)
    xl.sort()
    yl = util.set_to_list(y)
    yl.sort()

    if len(xl) != len(yl):
        return cmp(xl[0], yl[0])
    for v in zip(xl, yl):
        if v[0] != v[1]:
            return cmp(v[0], v[1])
    return 0

# Compare two avrules
def avrule_cmp(a, b):
    ret = id_set_cmp(a.src_types, b.src_types)
    if ret != 0:
        return ret
    ret = id_set_cmp(a.tgt_types, b.tgt_types)
    if ret != 0:
        return ret
    ret = id_set_cmp(a.obj_classes, b.obj_classes)
    if ret != 0:
        return ret

    # At this point, who cares - just return something
    return 0

# Compare two interface calls
def ifcall_cmp(a, b):
    if a.args[0] != b.args[0]:
        return cmp(a.args[0], b.args[0])
    return cmp(a.ifname, b.ifname)

# Compare an two avrules or interface calls
def rule_cmp(a, b):
    if isinstance(a, refpolicy.InterfaceCall):
        if isinstance(b, refpolicy.InterfaceCall):
            return ifcall_cmp(a, b)
        else:
            return id_set_cmp([a.args[0]], b.src_types)
    else:
        if isinstance(b, refpolicy.AVRule) or isinstance(b, refpolicy.AVExtRule):
            return avrule_cmp(a,b)
        else:
            return id_set_cmp(a.src_types, [b.args[0]])
                
def role_type_cmp(a, b):
    return cmp(a.role, b.role)

def sort_filter(module):
    """Sort and group the output for readability.
    """
    def sort_node(node):
        c = []

        # Module statement
        for mod in node.module_declarations():
            c.append(mod)
            c.append(refpolicy.Comment())

        # Requires
        for require in node.requires():
            c.append(require)
        c.append(refpolicy.Comment())

        # Rules
        #
        # We are going to group output by source type (which
        # we assume is the first argument for interfaces).
        rules = []
        rules.extend(node.avrules())
        rules.extend(node.avextrules())
        rules.extend(node.interface_calls())
        rules.sort(key=util.cmp_to_key(rule_cmp))

        cur = None
        sep_rules = []
        for rule in rules:
            if isinstance(rule, refpolicy.InterfaceCall):
                x = rule.args[0]
            else:
                x = util.first(rule.src_types)

            if cur != x:
                if cur:
                    sep_rules.append(refpolicy.Comment())
                cur = x
                comment = refpolicy.Comment()
                comment.lines.append("============= %s ==============" % cur)
                sep_rules.append(comment)
            sep_rules.append(rule)

        c.extend(sep_rules)


        ras = []
        ras.extend(node.role_types())
        ras.sort(key=util.cmp_to_key(role_type_cmp))
        if len(ras):
            comment = refpolicy.Comment()
            comment.lines.append("============= ROLES ==============")
            c.append(comment)
        

        c.extend(ras)

        # Everything else
        for child in node.children:
            if child not in c:
                c.append(child)

        node.children = c

    for node in module.nodes():
        sort_node(node)


