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
Classes for representing and manipulating interfaces.
"""

import copy
import itertools

from . import access
from . import refpolicy
from . import objectmodel
from . import matching
from .sepolgeni18n import _


class Param:
    """
    Object representing a parameter for an interface.
    """
    def __init__(self):
        self.__name = ""
        self.type = refpolicy.SRC_TYPE
        self.obj_classes = refpolicy.IdSet()
        self.required = True

    def set_name(self, name):
        if not access.is_idparam(name):
            raise ValueError("Name [%s] is not a param" % name)
        self.__name = name

    def get_name(self):
        return self.__name

    name = property(get_name, set_name)

    num = property(fget=lambda self: int(self.name[1:]))

    def __repr__(self):
        return "<sepolgen.policygen.Param instance [%s, %s, %s]>" % \
               (self.name, refpolicy.field_to_str[self.type], " ".join(self.obj_classes))


# Helper for extract perms
def __param_insert(name, type, av, params):
    ret = 0
    if name in params:
        p = params[name]
        # The entries are identical - we're done
        if type == p.type:
            return
        # Handle implicitly typed objects (like process)
        if (type == refpolicy.SRC_TYPE or type == refpolicy.TGT_TYPE) and \
           (p.type == refpolicy.TGT_TYPE or p.type == refpolicy.SRC_TYPE):
            #print name, refpolicy.field_to_str[p.type]
            # If the object is not implicitly typed, tell the
            # caller there is a likely conflict.
            ret = 1
            if av:
                avobjs = [av.obj_class]
            else:
                avobjs = []
            for obj in itertools.chain(p.obj_classes, avobjs):
                if obj in objectmodel.implicitly_typed_objects:
                    ret = 0
                    break
            # "Promote" to a SRC_TYPE as this is the likely usage.
            # We do this even if the above test fails on purpose
            # as there is really no sane way to resolve the conflict
            # here. The caller can take other actions if needed.
            p.type = refpolicy.SRC_TYPE
        else:
            # There is some conflict - no way to resolve it really
            # so we just leave the first entry and tell the caller
            # there was a conflict.
            ret = 1
    else:
        p = Param()
        p.name = name
        p.type = type
        params[p.name] = p

    if av:
        p.obj_classes.add(av.obj_class)
    return ret



def av_extract_params(av, params):
    """Extract the parameters from an access vector.

    Extract the parameters (in the form $N) from an access
    vector, storing them as Param objects in a dictionary.
    Some attempt is made at resolving conflicts with other
    entries in the dict, but if an unresolvable conflict is
    found it is reported to the caller.

    The goal here is to figure out how interface parameters are
    actually used in the interface - e.g., that $1 is a domain used as
    a SRC_TYPE. In general an interface will look like this:

    interface(`foo', `
       allow $1 foo : file read;
    ')

    This is simple to figure out - $1 is a SRC_TYPE. A few interfaces
    are more complex, for example:

    interface(`foo_trans',`
       domain_auto_trans($1,fingerd_exec_t,fingerd_t)

       allow $1 fingerd_t:fd use;
       allow fingerd_t $1:fd use;
       allow fingerd_t $1:fifo_file rw_file_perms;
       allow fingerd_t $1:process sigchld;
    ')

    Here the usage seems ambiguous, but it is not. $1 is still domain
    and therefore should be returned as a SRC_TYPE.

    Returns:
      0  - success
      1  - conflict found
    """
    ret = 0
    found_src = False
    if access.is_idparam(av.src_type):
        if __param_insert(av.src_type, refpolicy.SRC_TYPE, av, params) == 1:
            ret = 1

    if access.is_idparam(av.tgt_type):
        if __param_insert(av.tgt_type, refpolicy.TGT_TYPE, av, params) == 1:
            ret = 1

    if access.is_idparam(av.obj_class):
        if __param_insert(av.obj_class, refpolicy.OBJ_CLASS, av, params) == 1:
            ret = 1

    return ret

def role_extract_params(role, params):
    if access.is_idparam(role.role):
        return __param_insert(role.role, refpolicy.ROLE, None, params)
    
def type_rule_extract_params(rule, params):
    def extract_from_set(set, type):
        ret = 0
        for x in set:
            if access.is_idparam(x):
                if __param_insert(x, type, None, params):
                    ret = 1
        return ret

    ret = 0
    if extract_from_set(rule.src_types, refpolicy.SRC_TYPE):
        ret = 1

    if extract_from_set(rule.tgt_types, refpolicy.TGT_TYPE):
        ret = 1
        
    if extract_from_set(rule.obj_classes, refpolicy.OBJ_CLASS):
        ret = 1

    if access.is_idparam(rule.dest_type):
        if __param_insert(rule.dest_type, refpolicy.DEST_TYPE, None, params):
            ret = 1
            
    return ret

def ifcall_extract_params(ifcall, params):
    ret = 0
    for arg in ifcall.args:
        if access.is_idparam(arg):
            # Assume interface arguments are source types. Fairly safe
            # assumption for most interfaces
            if __param_insert(arg, refpolicy.SRC_TYPE, None, params):
                ret = 1

    return ret

class AttributeVector:
    def __init__(self):
        self.name = ""
        self.access = access.AccessVectorSet()

    def add_av(self, av):
        self.access.add_av(av)

class AttributeSet:
    def __init__(self):
        self.attributes = { }

    def add_attr(self, attr):
        self.attributes[attr.name] = attr

    def from_file(self, fd):
        def parse_attr(line):
            fields = line[1:-1].split()
            if len(fields) != 2 or fields[0] != "Attribute":
                raise SyntaxError("Syntax error Attribute statement %s" % line)
            a = AttributeVector()
            a.name = fields[1]

            return a

        a = None
        for line in fd:
            line = line[:-1]
            if line[0] == "[":
                if a:
                    self.add_attr(a)
                a = parse_attr(line)
            elif a:
                l = line.split(",")
                av = access.AccessVector(l)
                a.add_av(av)
        if a:
            self.add_attr(a)

class InterfaceVector:
    def __init__(self, interface=None, attributes={}):
        # Enabled is a loose concept currently - we are essentially
        # not enabling interfaces that we can't handle currently.
        # See InterfaceVector.add_ifv for more information.
        self.enabled = True
        self.name = ""
        # The access that is enabled by this interface - eventually
        # this will include indirect access from typeattribute
        # statements.
        self.access = access.AccessVectorSet()
        # Parameters are stored in a dictionary (key: param name
        # value: Param object).
        self.params = { }
        if interface:
            self.from_interface(interface, attributes)
        self.expanded = False

    def from_interface(self, interface, attributes={}):
        self.name = interface.name

        # Add allow rules
        for avrule in interface.avrules():
            if avrule.rule_type != refpolicy.AVRule.ALLOW:
                continue
            # Handle some policy bugs
            if "dontaudit" in interface.name:
                #print "allow rule in interface: %s" % interface
                continue
            avs = access.avrule_to_access_vectors(avrule)
            for av in avs:
                self.add_av(av)

        # Add typeattribute access
        if attributes:
            for typeattribute in interface.typeattributes():
                for attr in typeattribute.attributes:
                    if attr not in attributes.attributes:
                        # print "missing attribute " + attr
                        continue
                    attr_vec = attributes.attributes[attr]
                    for a in attr_vec.access:
                        av = copy.copy(a)
                        if av.src_type == attr_vec.name:
                            av.src_type = typeattribute.type
                        if av.tgt_type == attr_vec.name:
                            av.tgt_type = typeattribute.type
                        self.add_av(av)


        # Extract parameters from roles
        for role in interface.roles():
            if role_extract_params(role, self.params):
                pass
                #print "found conflicting role param %s for interface %s" % \
                #      (role.name, interface.name)
        # Extract parameters from type rules
        for rule in interface.typerules():
            if type_rule_extract_params(rule, self.params):
                pass
                #print "found conflicting params in rule %s in interface %s" % \
                #      (str(rule), interface.name)

        for ifcall in interface.interface_calls():
            if ifcall_extract_params(ifcall, self.params):
                pass
                #print "found conflicting params in ifcall %s in interface %s" % \
                #      (str(ifcall), interface.name)
            

    def add_av(self, av):
        if av_extract_params(av, self.params) == 1:
            pass
            #print "found conflicting perms [%s]" % str(av)
        self.access.add_av(av)

    def to_string(self):
        s = []
        s.append("[InterfaceVector %s]" % self.name)
        for av in self.access:
            s.append(str(av))
        return "\n".join(s)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<InterfaceVector %s:%s>" % (self.name, self.enabled)


class InterfaceSet:
    def __init__(self, output=None):
        self.interfaces = { }
        self.tgt_type_map = { }
        self.tgt_type_all = []
        self.output = output

    def o(self, str):
        if self.output:
            self.output.write(str + "\n")

    def to_file(self, fd):
        for iv in sorted(self.interfaces.values(), key=lambda x: x.name):
            fd.write("[InterfaceVector %s " % iv.name)
            for param in sorted(iv.params.values(), key=lambda x: x.name):
                fd.write("%s:%s " % (param.name, refpolicy.field_to_str[param.type]))
            fd.write("]\n")
            avl = sorted(iv.access.to_list())
            for av in avl:
                fd.write(",".join(av))
                fd.write("\n")

    def from_file(self, fd):
        def parse_ifv(line):
            fields = line[1:-1].split()
            if len(fields) < 2 or fields[0] != "InterfaceVector":
                raise SyntaxError("Syntax error InterfaceVector statement %s" % line)
            ifv = InterfaceVector()
            ifv.name = fields[1]
            if len(fields) == 2:
                return
            for field in fields[2:]:
                p = field.split(":")
                if len(p) != 2:
                    raise SyntaxError("Invalid param in InterfaceVector statement %s" % line)
                param = Param()
                param.name = p[0]
                param.type = refpolicy.str_to_field[p[1]]
                ifv.params[param.name] = param
            return ifv

        ifv = None
        for line in fd:
            line = line[:-1]
            if line[0] == "[":
                if ifv:
                    self.add_ifv(ifv)
                ifv = parse_ifv(line)
            elif ifv:
                l = line.split(",")
                av = access.AccessVector(l)
                ifv.add_av(av)
        if ifv:
            self.add_ifv(ifv)

        self.index()

    def add_ifv(self, ifv):
        self.interfaces[ifv.name] = ifv

    def index(self):
        for ifv in self.interfaces.values():
            tgt_types = set()
            for av in ifv.access:
                if access.is_idparam(av.tgt_type):
                    self.tgt_type_all.append(ifv)
                    tgt_types = set()
                    break
                tgt_types.add(av.tgt_type)

            for type in tgt_types:
                l = self.tgt_type_map.setdefault(type, [])
                l.append(ifv)

    def add(self, interface, attributes={}):
        ifv = InterfaceVector(interface, attributes)
        self.add_ifv(ifv)

    def add_headers(self, headers, output=None, attributes={}):
        for i in itertools.chain(headers.interfaces(), headers.templates()):
            self.add(i, attributes)

        self.expand_ifcalls(headers)
        self.index()

    def map_param(self, id, ifcall):
        if access.is_idparam(id):
            num = int(id[1:])
            if num > len(ifcall.args):
                # Tell caller to drop this because it must have
                # been generated from an optional param.
                return None
            else:
                arg = ifcall.args[num - 1]
                if isinstance(arg, list):
                    return arg
                else:
                    return [arg]
        else:
            return [id]

    def map_add_av(self, ifv, av, ifcall):
        src_types = self.map_param(av.src_type, ifcall)
        if src_types is None:
            return

        tgt_types = self.map_param(av.tgt_type, ifcall)
        if tgt_types is None:
            return

        obj_classes = self.map_param(av.obj_class, ifcall)
        if obj_classes is None:
            return

        new_perms = refpolicy.IdSet()
        for perm in av.perms:
            p = self.map_param(perm, ifcall)
            if p is None:
                continue
            else:
                new_perms.update(p)
        if len(new_perms) == 0:
            return

        for src_type in src_types:
            for tgt_type in tgt_types:
                for obj_class in obj_classes:
                    ifv.access.add(src_type, tgt_type, obj_class, new_perms)

    def do_expand_ifcalls(self, interface, if_by_name):
        # Descend an interface call tree adding the access
        # from each interface. This is a depth first walk
        # of the tree.

        stack = [(interface, None)]
        ifv = self.interfaces[interface.name]
        ifv.expanded = True

        while len(stack) > 0:
            cur, cur_ifcall = stack.pop(-1)

            cur_ifv = self.interfaces[cur.name]
            if cur != interface:

                for av in cur_ifv.access:
                    self.map_add_av(ifv, av, cur_ifcall)

                # If we have already fully expanded this interface
                # there is no reason to descend further.
                if cur_ifv.expanded:
                    continue

            for ifcall in cur.interface_calls():
                if ifcall.ifname == interface.name:
                    self.o(_("Found circular interface class"))
                    return
                try:
                    newif = if_by_name[ifcall.ifname]
                except KeyError:
                    self.o(_("Missing interface definition for %s" % ifcall.ifname))
                    continue

                stack.append((newif, ifcall))


    def expand_ifcalls(self, headers):
        # Create a map of interface names to interfaces -
        # this mirrors the interface vector map we already
        # have.
        if_by_name = { }

        for i in itertools.chain(headers.interfaces(), headers.templates()):
            if_by_name[i.name] = i


        for interface in itertools.chain(headers.interfaces(), headers.templates()):
            self.do_expand_ifcalls(interface, if_by_name)

