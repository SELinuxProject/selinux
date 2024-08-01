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
classes and algorithms for the generation of SELinux policy.
"""

import itertools
import textwrap

import selinux.audit2why as audit2why
try:
    from setools import *
except:
    pass

from . import refpolicy
from . import objectmodel
from . import access
from . import interfaces
from . import matching
from . import util
# Constants for the level of explanation from the generation
# routines
NO_EXPLANATION    = 0
SHORT_EXPLANATION = 1
LONG_EXPLANATION  = 2

class PolicyGenerator:
    """Generate a reference policy module from access vectors.

    PolicyGenerator generates a new reference policy module
    or updates an existing module based on requested access
    in the form of access vectors.

    It generates allow rules and optionally module require
    statements, reference policy interfaces, and extended
    permission access vector rules. By default only allow rules
    are generated. The methods .set_gen_refpol, .set_gen_requires
    and .set_gen_xperms turns on interface generation,
    requires generation, and xperms rules generation respectively.

    PolicyGenerator can also optionally add comments explaining
    why a particular access was allowed based on the audit
    messages that generated the access. The access vectors
    passed in must have the .audit_msgs field set correctly
    and .explain set to SHORT|LONG_EXPLANATION to enable this
    feature.

    The module created by PolicyGenerator can be passed to
    output.ModuleWriter to output a text representation.
    """
    def __init__(self, module=None):
        """Initialize a PolicyGenerator with an optional
        existing module.

        If the module parameter is not None then access
        will be added to the passed in module. Otherwise
        a new reference policy module will be created.
        """
        self.ifgen = None
        self.explain = NO_EXPLANATION
        self.gen_requires = False
        if module:
            self.module = module
        else:
            self.module = refpolicy.Module()

        self.dontaudit = False
        self.xperms = False

        self.domains = None
        self.gen_cil = False
        self.comment_start = '#'
    def set_gen_refpol(self, if_set=None, perm_maps=None):
        """Set whether reference policy interfaces are generated.

        To turn on interface generation pass in an interface set
        to use for interface generation. To turn off interface
        generation pass in None.

        If interface generation is enabled requires generation
        will also be enabled.
        """
        if if_set:
            self.ifgen = InterfaceGenerator(if_set, perm_maps)
            self.gen_requires = True
        else:
            self.ifgen = None
        self.__set_module_style()


    def set_gen_requires(self, status=True):
        """Set whether module requires are generated.

        Passing in true will turn on requires generation and
        False will disable generation. If requires generation is
        disabled interface generation will also be disabled and
        can only be re-enabled via .set_gen_refpol.
        """
        self.gen_requires = status

    def set_gen_explain(self, explain=SHORT_EXPLANATION):
        """Set whether access is explained.
        """
        self.explain = explain

    def set_gen_dontaudit(self, dontaudit):
        self.dontaudit = dontaudit

    def set_gen_xperms(self, xperms):
        """Set whether extended permission access vector rules
        are generated.
        """
        self.xperms = xperms

    def set_gen_cil(self, gen_cil):
        self.gen_cil = gen_cil
        if gen_cil:
            self.comment_start = ';'
        else:
            self.comment_start = '#'

    def __set_module_style(self):
        if self.ifgen:
            refpolicy = True
        else:
            refpolicy = False
        for mod in self.module.module_declarations():
            mod.refpolicy = refpolicy

    def set_module_name(self, name, version="1.0"):
        """Set the name of the module and optionally the version.
        """
        # find an existing module declaration
        m = None
        for mod in self.module.module_declarations():
            m = mod
        if not m:
            m = refpolicy.ModuleDeclaration()
            self.module.children.insert(0, m)
        m.name = name
        m.version = version
        if self.ifgen:
            m.refpolicy = True
        else:
            m.refpolicy = False

    def get_module(self):
        # Generate the requires
        if self.gen_requires:
            gen_requires(self.module)

        """Return the generated module"""
        return self.module

    def __add_av_rule(self, av):
        """Add access vector rule.
        """
        rule = refpolicy.AVRule(av)

        if self.dontaudit:
            rule.rule_type = rule.DONTAUDIT
        rule.comment = ""
        if self.explain:
            comment = refpolicy.Comment(explain_access(av, verbosity=self.explain))
            comment.set_gen_cil(self.gen_cil)
            rule.comment = str(comment)

        if av.type == audit2why.ALLOW:
            rule.comment += "\n%s!!!! This avc is allowed in the current policy" % self.comment_start

            if av.xperms:
                rule.comment += "\n%s!!!! This av rule may have been overridden by an extended permission av rule" % self.comment_start

        if av.type == audit2why.DONTAUDIT:
            rule.comment += "\n%s!!!! This avc has a dontaudit rule in the current policy" % self.comment_start

        if av.type == audit2why.BOOLEAN:
            if len(av.data) > 1:
                rule.comment += "\n%s!!!! This avc can be allowed using one of the these booleans:\n%s     %s" % (self.comment_start, self.comment_start, ", ".join([x[0] for x in av.data]))
            else:
                rule.comment += "\n%s!!!! This avc can be allowed using the boolean '%s'" % (self.comment_start, av.data[0][0])

        if av.type == audit2why.CONSTRAINT:
            rule.comment += "\n%s!!!! This avc is a constraint violation.  You would need to modify the attributes of either the source or target types to allow this access." % self.comment_start
            rule.comment += "\n%sConstraint rule: " % self.comment_start
            rule.comment += "\n%s\t" % self.comment_start + av.data[0]
            for reason in av.data[1:]:
                rule.comment += "\n%s" % self.comment_start
                rule.comment += "\tPossible cause is the source %s and target %s are different." % reason

        try:
            if ( av.type == audit2why.TERULE and
                 "write" in av.perms and
                 ( "dir" in av.obj_class or "open" in av.perms )):
                if not self.domains:
                    self.domains = seinfo(ATTRIBUTE, name="domain")[0]["types"]
                types=[]

                for i in [x[TCONTEXT] for x in sesearch([ALLOW], {SCONTEXT: av.src_type, CLASS: av.obj_class, PERMS: av.perms})]:
                    if i not in self.domains:
                        types.append(i)
                if len(types) == 1:
                    rule.comment += "\n%s!!!! The source type '%s' can write to a '%s' of the following type:\n%s %s\n" % (self.comment_start, av.src_type, av.obj_class, self.comment_start, ", ".join(types))
                elif len(types) >= 1:
                    rule.comment += "\n%s!!!! The source type '%s' can write to a '%s' of the following types:\n%s %s\n" % (self.comment_start, av.src_type, av.obj_class, self.comment_start, ", ".join(types))
        except:
            pass

        self.module.children.append(rule)

    def __add_ext_av_rules(self, av):
        """Add extended permission access vector rules.
        """
        for op in av.xperms.keys():
            extrule = refpolicy.AVExtRule(av, op)

            if self.dontaudit:
                extrule.rule_type = extrule.DONTAUDITXPERM

            self.module.children.append(extrule)

    def add_access(self, av_set):
        """Add the access from the access vector set to this
        module.
        """
        # Use the interface generator to split the access
        # into raw allow rules and interfaces. After this
        # a will contain a list of access that should be
        # used as raw allow rules and the interfaces will
        # be added to the module.
        if self.ifgen:
            raw_allow, ifcalls = self.ifgen.gen(av_set, self.explain)
            self.module.children.extend(ifcalls)
        else:
            raw_allow = av_set

        # Generate the raw allow rules from the filtered list
        for av in raw_allow:
            self.__add_av_rule(av)
            if self.xperms and av.xperms:
                self.__add_ext_av_rules(av)

    def add_role_types(self, role_type_set):
        for role_type in role_type_set:
            self.module.children.append(role_type)

def explain_access(av, ml=None, verbosity=SHORT_EXPLANATION):
    """Explain why a policy statement was generated.

    Return a string containing a text explanation of
    why a policy statement was generated. The string is
    commented and wrapped and can be directly inserted
    into a policy.

    Params:
      av - access vector representing the access. Should
       have .audit_msgs set appropriately.
      verbosity - the amount of explanation provided. Should
       be set to NO_EXPLANATION, SHORT_EXPLANATION, or
       LONG_EXPLANATION.
    Returns:
      list of strings - strings explaining the access or an empty
       string if verbosity=NO_EXPLANATION or there is not sufficient
       information to provide an explanation.
    """
    s = []

    def explain_interfaces():
        if not ml:
            return
        s.append(" Interface options:")
        for match in ml.all():
            ifcall = call_interface(match.interface, ml.av)
            s.append('   %s # [%d]' % (ifcall.to_string(), match.dist))


    # Format the raw audit data to explain why the
    # access was requested - either long or short.
    if verbosity == LONG_EXPLANATION:
        for msg in av.audit_msgs:
            s.append(' %s' % msg.header)
            s.append('  scontext="%s" tcontext="%s"' %
                     (str(msg.scontext), str(msg.tcontext)))
            s.append('  class="%s" perms="%s"' %
                     (msg.tclass, refpolicy.list_to_space_str(msg.accesses)))
            s.append('  comm="%s" exe="%s" path="%s"' % (msg.comm, msg.exe, msg.path))
            s.extend(textwrap.wrap('message="' + msg.message + '"', 80, initial_indent="  ",
                                   subsequent_indent="   "))
        explain_interfaces()
    elif verbosity:
        s.append(' src="%s" tgt="%s" class="%s", perms="%s"' %
                 (av.src_type, av.tgt_type, av.obj_class, av.perms.to_space_str()))
        # For the short display we are only going to use the additional information
        # from the first audit message. For the vast majority of cases this info
        # will always be the same anyway.
        if len(av.audit_msgs) > 0:
            msg = av.audit_msgs[0]
            s.append(' comm="%s" exe="%s" path="%s"' % (msg.comm, msg.exe, msg.path))
        explain_interfaces()
    return s

def call_interface(interface, av):
    params = []
    args = []

    params.extend(interface.params.values())
    params.sort(key=lambda param: param.num, reverse=True)

    ifcall = refpolicy.InterfaceCall()
    ifcall.ifname = interface.name

    for i in range(len(params)):
        if params[i].type == refpolicy.SRC_TYPE:
            ifcall.args.append(av.src_type)
        elif params[i].type == refpolicy.TGT_TYPE:
            ifcall.args.append(av.tgt_type)
        elif params[i].type == refpolicy.OBJ_CLASS:
            ifcall.args.append(av.obj_class)
        else:
            print(params[i].type)
            assert 0

    assert len(ifcall.args) > 0

    return ifcall

class InterfaceGenerator:
    def __init__(self, ifs, perm_maps=None):
        self.ifs = ifs
        self.hack_check_ifs(ifs)
        self.matcher = matching.AccessMatcher(perm_maps)
        self.calls = []

    def hack_check_ifs(self, ifs):
        # FIXME: Disable interfaces we can't call - this is a hack.
        # Because we don't handle roles, multiple parameters, etc.,
        # etc., we must make certain we can actually use a returned
        # interface.
        for x in ifs.interfaces.values():
            params = []
            params.extend(x.params.values())
            params.sort(key=lambda param: param.num, reverse=True)
            for i in range(len(params)):
                # Check that the parameter position matches
                # the number (e.g., $1 is the first arg). This
                # will fail if the parser missed something.
                if (i + 1) != params[i].num:
                    x.enabled = False
                    break
                # Check that we can handle the param type (currently excludes
                # roles.
                if params[i].type not in [refpolicy.SRC_TYPE, refpolicy.TGT_TYPE,
                                          refpolicy.OBJ_CLASS]:
                    x.enabled = False
                    break

    def gen(self, avs, verbosity):
        raw_av = self.match(avs)
        ifcalls = []
        for ml in self.calls:
            ifcall = call_interface(ml.best().interface, ml.av)
            if verbosity:
                ifcall.comment = refpolicy.Comment(explain_access(ml.av, ml, verbosity))
            ifcalls.append((ifcall, ml))

        d = []
        for ifcall, ifs in ifcalls:
            found = False
            for o_ifcall in d:
                if o_ifcall.matches(ifcall):
                    if o_ifcall.comment and ifcall.comment:
                        o_ifcall.comment.merge(ifcall.comment)
                    found = True
            if not found:
                d.append(ifcall)

        return (raw_av, d)


    def match(self, avs):
        raw_av = []
        for av in avs:
            ans = matching.MatchList()
            self.matcher.search_ifs(self.ifs, av, ans)
            if len(ans):
                self.calls.append(ans)
            else:
                raw_av.append(av)

        return raw_av


def gen_requires(module):
    """Add require statements to the module.
    """
    def collect_requires(node):
        r = refpolicy.Require()
        for avrule in node.avrules():
            r.types.update(avrule.src_types)
            r.types.update(avrule.tgt_types)
            for obj in avrule.obj_classes:
                r.add_obj_class(obj, avrule.perms)

        for ifcall in node.interface_calls():
            for arg in ifcall.args:
                # FIXME - handle non-type arguments when we
                # can actually figure those out.
                r.types.add(arg)

        for role_type in node.role_types():
            r.roles.add(role_type.role)
            r.types.update(role_type.types)
                
        r.types.discard("self")

        node.children.insert(0, r)

    # FUTURE - this is untested on modules with any sort of
    # nesting
    for node in module.nodes():
        collect_requires(node)


