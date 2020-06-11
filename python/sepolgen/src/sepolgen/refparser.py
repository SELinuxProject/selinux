# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006-2007 Red Hat
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

# OVERVIEW
#
#
# This is a parser for the refpolicy policy "language" - i.e., the
# normal SELinux policy language plus the refpolicy style M4 macro
# constructs on top of that base language. This parser is primarily
# aimed at parsing the policy headers in order to create an abstract
# policy representation suitable for generating policy.
#
# Both the lexer and parser are included in this file. The are implemented
# using the Ply library (included with sepolgen).

import sys
import os
import re
import traceback

from . import access
from . import defaults
from . import lex
from . import refpolicy
from . import yacc

# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#
# lexer
#
# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

tokens = (
    # basic tokens, punctuation
    'TICK',
    'SQUOTE',
    'OBRACE',
    'CBRACE',
    'SEMI',
    'COLON',
    'OPAREN',
    'CPAREN',
    'COMMA',
    'MINUS',
    'TILDE',
    'ASTERISK',
    'AMP',
    'BAR',
    'EXPL',
    'EQUAL',
    'FILENAME',
    'IDENTIFIER',
    'NUMBER',
    'PATH',
    'IPV6_ADDR',
    # reserved words
    #   module
    'MODULE',
    'POLICY_MODULE',
    'REQUIRE',
    #   flask
    'SID',
    'GENFSCON',
    'FS_USE_XATTR',
    'FS_USE_TRANS',
    'FS_USE_TASK',
    'PORTCON',
    'NODECON',
    'NETIFCON',
    'PIRQCON',
    'IOMEMCON',
    'IOPORTCON',
    'PCIDEVICECON',
    'DEVICETREECON',
    #   object classes
    'CLASS',
    #   types and attributes
    'TYPEATTRIBUTE',
    'ROLEATTRIBUTE',
    'TYPE',
    'ATTRIBUTE',
    'ATTRIBUTE_ROLE',
    'ALIAS',
    'TYPEALIAS',
    #   conditional policy
    'BOOL',
    'TRUE',
    'FALSE',
    'IF',
    'ELSE',
    #   users and roles
    'ROLE',
    'TYPES',
    #   rules
    'ALLOW',
    'DONTAUDIT',
    'AUDITALLOW',
    'NEVERALLOW',
    'PERMISSIVE',
    'TYPEBOUNDS',
    'TYPE_TRANSITION',
    'TYPE_CHANGE',
    'TYPE_MEMBER',
    'RANGE_TRANSITION',
    'ROLE_TRANSITION',
    #   refpolicy keywords
    'OPT_POLICY',
    'INTERFACE',
    'TUNABLE_POLICY',
    'GEN_REQ',
    'TEMPLATE',
    'GEN_CONTEXT',
    'GEN_TUNABLE',
    #   m4
    'IFELSE',
    'IFDEF',
    'IFNDEF',
    'DEFINE'
    )

# All reserved keywords - see t_IDENTIFIER for how these are matched in
# the lexer.
reserved = {
    # module
    'module' : 'MODULE',
    'policy_module' : 'POLICY_MODULE',
    'require' : 'REQUIRE',
    # flask
    'sid' : 'SID',
    'genfscon' : 'GENFSCON',
    'fs_use_xattr' : 'FS_USE_XATTR',
    'fs_use_trans' : 'FS_USE_TRANS',
    'fs_use_task' : 'FS_USE_TASK',
    'portcon' : 'PORTCON',
    'nodecon' : 'NODECON',
    'netifcon' : 'NETIFCON',
    'pirqcon' : 'PIRQCON',
    'iomemcon' : 'IOMEMCON',
    'ioportcon' : 'IOPORTCON',
    'pcidevicecon' : 'PCIDEVICECON',
    'devicetreecon' : 'DEVICETREECON',
    # object classes
    'class' : 'CLASS',
    # types and attributes
    'typeattribute' : 'TYPEATTRIBUTE',
    'roleattribute' : 'ROLEATTRIBUTE',
    'type' : 'TYPE',
    'attribute' : 'ATTRIBUTE',
    'attribute_role' : 'ATTRIBUTE_ROLE',
    'alias' : 'ALIAS',
    'typealias' : 'TYPEALIAS',
    # conditional policy
    'bool' : 'BOOL',
    'true' : 'TRUE',
    'false' : 'FALSE',
    'if' : 'IF',
    'else' : 'ELSE',
    # users and roles
    'role' : 'ROLE',
    'types' : 'TYPES',
    # rules
    'allow' : 'ALLOW',
    'dontaudit' : 'DONTAUDIT',
    'auditallow' : 'AUDITALLOW',
    'neverallow' : 'NEVERALLOW',
    'permissive' : 'PERMISSIVE',
    'typebounds' : 'TYPEBOUNDS',
    'type_transition' : 'TYPE_TRANSITION',
    'type_change' : 'TYPE_CHANGE',
    'type_member' : 'TYPE_MEMBER',
    'range_transition' : 'RANGE_TRANSITION',
    'role_transition' : 'ROLE_TRANSITION',
    # refpolicy keywords
    'optional_policy' : 'OPT_POLICY',
    'interface' : 'INTERFACE',
    'tunable_policy' : 'TUNABLE_POLICY',
    'gen_require' : 'GEN_REQ',
    'template' : 'TEMPLATE',
    'gen_context' : 'GEN_CONTEXT',
    'gen_tunable' : 'GEN_TUNABLE',
    # M4
    'ifelse' : 'IFELSE',
    'ifndef' : 'IFNDEF',
    'ifdef' : 'IFDEF',
    'define' : 'DEFINE'
    }

# The ply lexer allows definition of tokens in 2 ways: regular expressions
# or functions.

# Simple regex tokens
t_TICK      = r'\`'
t_SQUOTE    = r'\''
t_OBRACE    = r'\{'
t_CBRACE    = r'\}'
# This will handle spurious extra ';' via the +
t_SEMI      = r'\;+'
t_COLON     = r'\:'
t_OPAREN    = r'\('
t_CPAREN    = r'\)'
t_COMMA     = r'\,'
t_MINUS     = r'\-'
t_TILDE     = r'\~'
t_ASTERISK  = r'\*'
t_AMP       = r'\&'
t_BAR       = r'\|'
t_EXPL      = r'\!'
t_EQUAL     = r'\='
t_NUMBER    = r'[0-9\.]+'
t_PATH      = r'/[a-zA-Z0-9)_\.\*/\$]*'
#t_IPV6_ADDR = r'[a-fA-F0-9]{0,4}:[a-fA-F0-9]{0,4}:([a-fA-F0-9]{0,4}:)*'

# Ignore whitespace - this is a special token for ply that more efficiently
# ignores uninteresting tokens.
t_ignore    = " \t"

# More complex tokens
def t_IPV6_ADDR(t):
    r'[a-fA-F0-9]{0,4}:[a-fA-F0-9]{0,4}:([a-fA-F0-9]|:)*'
    # This is a function simply to force it sooner into
    # the regex list
    return t

def t_m4comment(t):
    r'dnl.*\n'
    # Ignore all comments
    t.lexer.lineno += 1

def t_refpolicywarn1(t):
    r'define.*refpolicywarn\(.*\n'
    # Ignore refpolicywarn statements - they sometimes
    # contain text that we can't parse.
    t.skip(1)

def t_refpolicywarn(t):
    r'refpolicywarn\(.*\n'
    # Ignore refpolicywarn statements - they sometimes
    # contain text that we can't parse.
    t.lexer.lineno += 1

def t_IDENTIFIER(t):
    r'[a-zA-Z_\$][a-zA-Z0-9_\-\+\.\$\*~]*'
    # Handle any keywords
    t.type = reserved.get(t.value,'IDENTIFIER')
    return t

def t_FILENAME(t):
    r'\"[a-zA-Z0-9_\-\+\.\$\*~ :]+\"'
    # Handle any keywords
    t.type = reserved.get(t.value,'FILENAME')
    return t

def t_comment(t):
    r'\#.*\n'
    # Ignore all comments
    t.lexer.lineno += 1

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.skip(1)

def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)

# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#
# Parser
#
# :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

# Global data used during parsing - making it global is easier than
# passing the state through the parsing functions.

#   m is the top-level data structure (stands for modules).
m = None
#   error is either None (indicating no error) or a string error message.
error = None
parse_file = ""
#   spt is the support macros (e.g., obj/perm sets) - it is an instance of
#     refpolicy.SupportMacros and should always be present during parsing
#     though it may not contain any macros.
spt = None
success = True

# utilities
def collect(stmts, parent, val=None):
    if stmts is None:
        return
    for s in stmts:
        if s is None:
            continue
        s.parent = parent
        if val is not None:
            parent.children.insert(0, (val, s))
        else:
            parent.children.insert(0, s)

def expand(ids, s):
    for id in ids:
        if spt.has_key(id):  # noqa
            s.update(spt.by_name(id))
        else:
            s.add(id)

# Top-level non-terminal
def p_statements(p):
    '''statements : statement
                  | statements statement
                  | empty
    '''
    if len(p) == 2 and p[1]:
        m.children.append(p[1])
    elif len(p) > 2 and p[2]:
        m.children.append(p[2])

def p_statement(p):
    '''statement : interface
                 | template
                 | obj_perm_set
                 | policy
                 | policy_module_stmt
                 | module_stmt
    '''
    p[0] = p[1]

def p_empty(p):
    'empty :'
    pass

#
# Reference policy language constructs
#

# This is for the policy module statement (e.g., policy_module(foo,1.2.0)).
# We have a separate terminal for either the basic language module statement
# and interface calls to make it easier to identifier.
def p_policy_module_stmt(p):
    'policy_module_stmt : POLICY_MODULE OPAREN IDENTIFIER COMMA NUMBER CPAREN'
    m = refpolicy.ModuleDeclaration()
    m.name = p[3]
    m.version = p[5]
    m.refpolicy = True
    p[0] = m

def p_interface(p):
    '''interface : INTERFACE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
    '''
    x = refpolicy.Interface(p[4])
    collect(p[8], x)
    p[0] = x

def p_template(p):
    '''template : TEMPLATE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
                | DEFINE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
    '''
    x = refpolicy.Template(p[4])
    collect(p[8], x)
    p[0] = x

def p_define(p):
    '''define : DEFINE OPAREN TICK IDENTIFIER SQUOTE CPAREN'''
    # This is for defining single M4 values (to be used later in ifdef statements).
    # Example: define(`sulogin_no_pam'). We don't currently do anything with these
    # but we should in the future when we correctly resolve ifdef statements.
    p[0] = None

def p_interface_stmts(p):
    '''interface_stmts : policy
                       | interface_stmts policy
                       | empty
    '''
    if len(p) == 2 and p[1]:
        p[0] = p[1]
    elif len(p) > 2:
        if not p[1]:
            if p[2]:
                p[0] = p[2]
        elif not p[2]:
            p[0] = p[1]
        else:
            p[0] = p[1] + p[2]

def p_optional_policy(p):
    '''optional_policy : OPT_POLICY OPAREN TICK interface_stmts SQUOTE CPAREN
                       | OPT_POLICY OPAREN TICK interface_stmts SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
    '''
    o = refpolicy.OptionalPolicy()
    collect(p[4], o, val=True)
    if len(p) > 7:
        collect(p[8], o, val=False)
    p[0] = [o]

def p_tunable_policy(p):
    '''tunable_policy : TUNABLE_POLICY OPAREN TICK cond_expr SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
                      | TUNABLE_POLICY OPAREN TICK cond_expr SQUOTE COMMA TICK interface_stmts SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN
    '''
    x = refpolicy.TunablePolicy()
    x.cond_expr = p[4]
    collect(p[8], x, val=True)
    if len(p) > 11:
        collect(p[12], x, val=False)
    p[0] = [x]

def p_ifelse(p):
    '''ifelse : IFELSE OPAREN TICK IDENTIFIER SQUOTE COMMA COMMA TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
              | IFELSE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
              | IFELSE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK SQUOTE COMMA TICK interface_stmts SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
    '''
#    x = refpolicy.IfDef(p[4])
#    v = True
#    collect(p[8], x, val=v)
#    if len(p) > 12:
#        collect(p[12], x, val=False)
#    p[0] = [x]
    pass


def p_ifdef(p):
    '''ifdef : IFDEF OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
             | IFNDEF OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
             | IFDEF OPAREN TICK IDENTIFIER SQUOTE COMMA TICK interface_stmts SQUOTE COMMA TICK interface_stmts SQUOTE CPAREN optional_semi
    '''
    x = refpolicy.IfDef(p[4])
    if p[1] == 'ifdef':
        v = True
    else:
        v = False
    collect(p[8], x, val=v)
    if len(p) > 12:
        collect(p[12], x, val=False)
    p[0] = [x]

def p_interface_call(p):
    '''interface_call : IDENTIFIER OPAREN interface_call_param_list CPAREN
                      | IDENTIFIER OPAREN CPAREN
                      | IDENTIFIER OPAREN interface_call_param_list CPAREN SEMI'''
    # Allow spurious semi-colons at the end of interface calls
    i = refpolicy.InterfaceCall(ifname=p[1])
    if len(p) > 4:
        i.args.extend(p[3])
    p[0] = i

def p_interface_call_param(p):
    '''interface_call_param : IDENTIFIER
                            | IDENTIFIER MINUS IDENTIFIER
                            | nested_id_set
                            | TRUE
                            | FALSE
                            | FILENAME
    '''
    # Intentionally let single identifiers pass through
    # List means set, non-list identifier
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = [p[1], "-" + p[3]]

def p_interface_call_param_list(p):
    '''interface_call_param_list : interface_call_param
                                 | interface_call_param_list COMMA interface_call_param
    '''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[3]]


def p_obj_perm_set(p):
    'obj_perm_set : DEFINE OPAREN TICK IDENTIFIER SQUOTE COMMA TICK names SQUOTE CPAREN'
    s = refpolicy.ObjPermSet(p[4])
    s.perms = p[8]
    p[0] = s
    
#
# Basic SELinux policy language
#

def p_policy(p):
    '''policy : policy_stmt
              | optional_policy
              | tunable_policy
              | ifdef
              | ifelse
              | conditional
    '''
    p[0] = p[1]

def p_policy_stmt(p):
    '''policy_stmt : gen_require
                   | avrule_def
                   | typerule_def
                   | typebound_def
                   | typeattribute_def
                   | roleattribute_def
                   | interface_call
                   | role_def
                   | role_allow
                   | permissive
                   | type_def
                   | typealias_def
                   | attribute_def
                   | attribute_role_def
                   | range_transition_def
                   | role_transition_def
                   | bool
                   | gen_tunable
                   | define
                   | initial_sid
                   | genfscon
                   | fs_use
                   | portcon
                   | nodecon
                   | netifcon
                   | pirqcon
                   | iomemcon
                   | ioportcon
                   | pcidevicecon
                   | devicetreecon
    '''
    if p[1]:
        p[0] = [p[1]]

def p_module_stmt(p):
    'module_stmt : MODULE IDENTIFIER NUMBER SEMI'
    m = refpolicy.ModuleDeclaration()
    m.name = p[2]
    m.version = p[3]
    m.refpolicy = False
    p[0] = m

def p_gen_require(p):
    '''gen_require : GEN_REQ OPAREN TICK requires SQUOTE CPAREN
                   | REQUIRE OBRACE requires CBRACE'''
    # We ignore the require statements - they are redundant data from our point-of-view.
    # Checkmodule will verify them later anyway so we just assume that they match what
    # is in the rest of the interface.
    pass

def p_requires(p):
    '''requires : require
                | requires require
                | ifdef
                | requires ifdef
    '''
    pass

def p_require(p):
    '''require : TYPE comma_list SEMI
               | ROLE comma_list SEMI
               | ATTRIBUTE comma_list SEMI
               | ATTRIBUTE_ROLE comma_list SEMI
               | CLASS comma_list SEMI
               | BOOL comma_list SEMI
    '''
    pass

def p_security_context(p):
    '''security_context : IDENTIFIER COLON IDENTIFIER COLON IDENTIFIER
                        | IDENTIFIER COLON IDENTIFIER COLON IDENTIFIER COLON mls_range_def'''
    # This will likely need some updates to handle complex levels
    s = refpolicy.SecurityContext()
    s.user = p[1]
    s.role = p[3]
    s.type = p[5]
    if len(p) > 6:
        s.level = p[7]

    p[0] = s

def p_gen_context(p):
    '''gen_context : GEN_CONTEXT OPAREN security_context COMMA mls_range_def CPAREN
    '''
    # We actually store gen_context statements in a SecurityContext
    # object - it knows how to output either a bare context or a
    # gen_context statement.
    s = p[3]
    s.level = p[5]
    
    p[0] = s

def p_context(p):
    '''context : security_context
               | gen_context
    '''
    p[0] = p[1]

def p_initial_sid(p):
    '''initial_sid : SID IDENTIFIER context'''
    s = refpolicy.InitialSid()
    s.name = p[2]
    s.context = p[3]
    p[0] = s

def p_genfscon(p):
    '''genfscon : GENFSCON IDENTIFIER PATH context'''
    
    g = refpolicy.GenfsCon()
    g.filesystem = p[2]
    g.path = p[3]
    g.context = p[4]

    p[0] = g

def p_fs_use(p):
    '''fs_use : FS_USE_XATTR IDENTIFIER context SEMI
              | FS_USE_TASK IDENTIFIER context SEMI
              | FS_USE_TRANS IDENTIFIER context SEMI
    '''
    f = refpolicy.FilesystemUse()
    if p[1] == "fs_use_xattr":
        f.type = refpolicy.FilesystemUse.XATTR
    elif p[1] == "fs_use_task":
        f.type = refpolicy.FilesystemUse.TASK
    elif p[1] == "fs_use_trans":
        f.type = refpolicy.FilesystemUse.TRANS

    f.filesystem = p[2]
    f.context = p[3]

    p[0] = f

def p_portcon(p):
    '''portcon : PORTCON IDENTIFIER NUMBER context
               | PORTCON IDENTIFIER NUMBER MINUS NUMBER context'''
    c = refpolicy.PortCon()
    c.port_type = p[2]
    if len(p) == 5:
        c.port_number = p[3]
        c.context = p[4]
    else:
        c.port_number = p[3] + "-" + p[4]
        c.context = p[5]

    p[0] = c

def p_nodecon(p):
    '''nodecon : NODECON NUMBER NUMBER context
               | NODECON IPV6_ADDR IPV6_ADDR context
    '''
    n = refpolicy.NodeCon()
    n.start = p[2]
    n.end = p[3]
    n.context = p[4]

    p[0] = n

def p_netifcon(p):
    'netifcon : NETIFCON IDENTIFIER context context'
    n = refpolicy.NetifCon()
    n.interface = p[2]
    n.interface_context = p[3]
    n.packet_context = p[4]

    p[0] = n

def p_pirqcon(p):
    'pirqcon : PIRQCON NUMBER context'
    c = refpolicy.PirqCon()
    c.pirq_number = p[2]
    c.context = p[3]

    p[0] = c

def p_iomemcon(p):
    '''iomemcon : IOMEMCON NUMBER context
                | IOMEMCON NUMBER MINUS NUMBER context'''
    c = refpolicy.IomemCon()
    if len(p) == 4:
        c.device_mem = p[2]
        c.context = p[3]
    else:
        c.device_mem = p[2] + "-" + p[3]
        c.context = p[4]

    p[0] = c

def p_ioportcon(p):
    '''ioportcon : IOPORTCON NUMBER context
                | IOPORTCON NUMBER MINUS NUMBER context'''
    c = refpolicy.IoportCon()
    if len(p) == 4:
        c.ioport = p[2]
        c.context = p[3]
    else:
        c.ioport = p[2] + "-" + p[3]
        c.context = p[4]

    p[0] = c

def p_pcidevicecon(p):
    'pcidevicecon : PCIDEVICECON NUMBER context'
    c = refpolicy.PciDeviceCon()
    c.device = p[2]
    c.context = p[3]

    p[0] = c

def p_devicetreecon(p):
    'devicetreecon : DEVICETREECON NUMBER context'
    c = refpolicy.DevicetTeeCon()
    c.path = p[2]
    c.context = p[3]

    p[0] = c

def p_mls_range_def(p):
    '''mls_range_def : mls_level_def MINUS mls_level_def
                     | mls_level_def
    '''
    p[0] = p[1]
    if len(p) > 2:
        p[0] = p[0] + "-" + p[3]

def p_mls_level_def(p):
    '''mls_level_def : IDENTIFIER COLON comma_list
                     | IDENTIFIER
    '''
    p[0] = p[1]
    if len(p) > 2:
        p[0] = p[0] + ":" + ",".join(p[3])
    
def p_type_def(p):
    '''type_def : TYPE IDENTIFIER COMMA comma_list SEMI
                | TYPE IDENTIFIER SEMI
                | TYPE IDENTIFIER ALIAS names SEMI
                | TYPE IDENTIFIER ALIAS names COMMA comma_list SEMI
    '''
    t = refpolicy.Type(p[2])
    if len(p) == 6:
        if p[3] == ',':
            t.attributes.update(p[4])
        else:
            t.aliases = p[4]
    elif len(p) > 4:
        t.aliases = p[4]
        if len(p) == 8:
            t.attributes.update(p[6])
    p[0] = t

def p_attribute_def(p):
    'attribute_def : ATTRIBUTE IDENTIFIER SEMI'
    a = refpolicy.Attribute(p[2])
    p[0] = a

def p_attribute_role_def(p):
    'attribute_role_def : ATTRIBUTE_ROLE IDENTIFIER SEMI'
    a = refpolicy.Attribute_Role(p[2])
    p[0] = a

def p_typealias_def(p):
    'typealias_def : TYPEALIAS IDENTIFIER ALIAS names SEMI'
    t = refpolicy.TypeAlias()
    t.type = p[2]
    t.aliases = p[4]
    p[0] = t

def p_role_def(p):
    '''role_def : ROLE IDENTIFIER TYPES comma_list SEMI
                | ROLE IDENTIFIER SEMI'''
    r = refpolicy.Role()
    r.role = p[2]
    if len(p) > 4:
        r.types.update(p[4])
    p[0] = r

def p_role_allow(p):
    'role_allow : ALLOW names names SEMI'
    r = refpolicy.RoleAllow()
    r.src_roles = p[2]
    r.tgt_roles = p[3]
    p[0] = r

def p_permissive(p):
    'permissive : PERMISSIVE names SEMI'
    pass

def p_avrule_def(p):
    '''avrule_def : ALLOW names names COLON names names SEMI
                  | DONTAUDIT names names COLON names names SEMI
                  | AUDITALLOW names names COLON names names SEMI
                  | NEVERALLOW names names COLON names names SEMI
    '''
    a = refpolicy.AVRule()
    if p[1] == 'dontaudit':
        a.rule_type = refpolicy.AVRule.DONTAUDIT
    elif p[1] == 'auditallow':
        a.rule_type = refpolicy.AVRule.AUDITALLOW
    elif p[1] == 'neverallow':
        a.rule_type = refpolicy.AVRule.NEVERALLOW
    a.src_types = p[2]
    a.tgt_types = p[3]
    a.obj_classes = p[5]
    a.perms = p[6]
    p[0] = a

def p_typerule_def(p):
    '''typerule_def : TYPE_TRANSITION names names COLON names IDENTIFIER SEMI
                    | TYPE_TRANSITION names names COLON names IDENTIFIER FILENAME SEMI
                    | TYPE_TRANSITION names names COLON names IDENTIFIER IDENTIFIER SEMI
                    | TYPE_CHANGE names names COLON names IDENTIFIER SEMI
                    | TYPE_MEMBER names names COLON names IDENTIFIER SEMI
    '''
    t = refpolicy.TypeRule()
    if p[1] == 'type_change':
        t.rule_type = refpolicy.TypeRule.TYPE_CHANGE
    elif p[1] == 'type_member':
        t.rule_type = refpolicy.TypeRule.TYPE_MEMBER
    t.src_types = p[2]
    t.tgt_types = p[3]
    t.obj_classes = p[5]
    t.dest_type = p[6]
    t.file_name = p[7]
    p[0] = t

def p_typebound_def(p):
    '''typebound_def : TYPEBOUNDS IDENTIFIER comma_list SEMI'''
    t = refpolicy.TypeBound()
    t.type = p[2]
    t.tgt_types.update(p[3])
    p[0] = t

def p_bool(p):
    '''bool : BOOL IDENTIFIER TRUE SEMI
            | BOOL IDENTIFIER FALSE SEMI'''
    b = refpolicy.Bool()
    b.name = p[2]
    if p[3] == "true":
        b.state = True
    else:
        b.state = False
    p[0] = b

def p_gen_tunable(p):
    '''gen_tunable : GEN_TUNABLE OPAREN TICK IDENTIFIER SQUOTE COMMA TRUE CPAREN
                   | GEN_TUNABLE OPAREN TICK IDENTIFIER SQUOTE COMMA FALSE CPAREN'''
    b = refpolicy.Bool()
    b.name = p[4]
    if p[7] == "true":
        b.state = True
    else:
        b.state = False
    p[0] = b

def p_conditional(p):
    ''' conditional : IF OPAREN cond_expr CPAREN OBRACE interface_stmts CBRACE
                    | IF OPAREN cond_expr CPAREN OBRACE interface_stmts CBRACE ELSE OBRACE interface_stmts CBRACE
    '''
    c = refpolicy.Conditional()
    c.cond_expr = p[3]
    collect(p[6], c, val=True)
    if len(p) > 8:
        collect(p[10], c, val=False)
    p[0] = [c]

def p_typeattribute_def(p):
    '''typeattribute_def : TYPEATTRIBUTE IDENTIFIER comma_list SEMI'''
    t = refpolicy.TypeAttribute()
    t.type = p[2]
    t.attributes.update(p[3])
    p[0] = t

def p_roleattribute_def(p):
    '''roleattribute_def : ROLEATTRIBUTE IDENTIFIER comma_list SEMI'''
    t = refpolicy.RoleAttribute()
    t.role = p[2]
    t.roleattributes.update(p[3])
    p[0] = t

def p_range_transition_def(p):
    '''range_transition_def : RANGE_TRANSITION names names COLON names mls_range_def SEMI
                            | RANGE_TRANSITION names names names SEMI'''
    pass

def p_role_transition_def(p):
    '''role_transition_def : ROLE_TRANSITION names names names SEMI'''
    pass

def p_cond_expr(p):
    '''cond_expr : IDENTIFIER
                 | EXPL cond_expr
                 | cond_expr AMP AMP cond_expr
                 | cond_expr BAR BAR cond_expr
                 | cond_expr EQUAL EQUAL cond_expr
                 | cond_expr EXPL EQUAL cond_expr
    '''
    l = len(p)
    if l == 2:
        p[0] = [p[1]]
    elif l == 3:
        p[0] = [p[1]] + p[2]
    else:
        p[0] = p[1] + [p[2] + p[3]] + p[4]


#
# Basic terminals
#

# Identifiers and lists of identifiers. These must
# be handled somewhat gracefully. Names returns an IdSet and care must
# be taken that this is _assigned_ to an object to correctly update
# all of the flags (as opposed to using update). The other terminals
# return list - this is to preserve ordering if it is important for
# parsing (for example, interface_call must retain the ordering). Other
# times the list should be used to update an IdSet.

def p_names(p):
    '''names : identifier
             | nested_id_set
             | asterisk
             | TILDE identifier
             | TILDE nested_id_set
             | IDENTIFIER MINUS IDENTIFIER
    '''
    s = refpolicy.IdSet()
    if len(p) < 3:
        expand(p[1], s)
    elif len(p) == 3:
        expand(p[2], s)
        s.compliment = True
    else:
        expand([p[1]])
        s.add("-" + p[3])
    p[0] = s

def p_identifier(p):
    'identifier : IDENTIFIER'
    p[0] = [p[1]]

def p_asterisk(p):
    'asterisk : ASTERISK'
    p[0] = [p[1]]

def p_nested_id_set(p):
    '''nested_id_set : OBRACE nested_id_list CBRACE
    '''
    p[0] = p[2]

def p_nested_id_list(p):
    '''nested_id_list : nested_id_element
                      | nested_id_list nested_id_element
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + p[2]

def p_nested_id_element(p):
    '''nested_id_element : identifier
                         | MINUS IDENTIFIER
                         | nested_id_set
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        # For now just leave the '-'
        str = "-" + p[2]
        p[0] = [str]

def p_comma_list(p):
    '''comma_list : nested_id_list
                  | comma_list COMMA nested_id_list
    '''
    if len(p) > 2:
        p[1] = p[1] + p[3]
    p[0] = p[1]

def p_optional_semi(p):
    '''optional_semi : SEMI
                   | empty'''
    pass


#
# Interface to the parser
#

def p_error(tok):
    global error, parse_file, success, parser
    error = "%s: Syntax error on line %d %s [type=%s]" % (parse_file, tok.lineno, tok.value, tok.type)
    print(error)
    success = False

def prep_spt(spt):
    if not spt:
        return { }
    map = {}
    for x in spt:
        map[x.name] = x

parser = None
lexer = None
def create_globals(module, support, debug):
    global parser, lexer, m, spt

    if not parser:
        lexer = lex.lex()
        parser = yacc.yacc(method="LALR", debug=debug, write_tables=0)

    if module is not None:
        m = module
    else:
        m = refpolicy.Module()

    if not support:
        spt = refpolicy.SupportMacros()
    else:
        spt = support

def parse(text, module=None, support=None, debug=False):
    create_globals(module, support, debug)
    global error, parser, lexer, success

    lexer.lineno = 1
    success = True

    try:
        parser.parse(text, debug=debug, lexer=lexer)
    except Exception as e:
        parser = None
        lexer = None
        error = "internal parser error: %s" % str(e) + "\n" + traceback.format_exc()

    if not success:
        # force the parser and lexer to be rebuilt - we have some problems otherwise
        parser = None
        msg = 'could not parse text: "%s"' % error
        raise ValueError(msg)
    return m

def list_headers(root):
    modules = []
    support_macros = None

    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            modname = os.path.splitext(name)
            filename = os.path.join(dirpath, name)

            if modname[1] == '.spt':
                if name == "obj_perm_sets.spt":
                    support_macros = filename
                elif len(re.findall("patterns", modname[0])):
                    modules.append((modname[0], filename))
            elif modname[1] == '.if':
                modules.append((modname[0], filename))

    return (modules, support_macros)


def parse_headers(root, output=None, expand=True, debug=False):
    from . import util

    headers = refpolicy.Headers()

    modules = []
    support_macros = None

    if os.path.isfile(root):
        name = os.path.split(root)[1]
        if name == '':
            raise ValueError("Invalid file name %s" % root)
        modname = os.path.splitext(name)
        modules.append((modname[0], root))
        all_modules, support_macros = list_headers(defaults.headers())
    else:
        modules, support_macros = list_headers(root)

    if expand and not support_macros:
        raise ValueError("could not find support macros (obj_perm_sets.spt)")

    def o(msg):
        if output:
            output.write(msg)

    def parse_file(f, module, spt=None):
        global parse_file
        if debug:
            o("parsing file %s\n" % f)
        try:
            fd = open(f)
            txt = fd.read()
            fd.close()
            parse_file = f
            parse(txt, module, spt, debug)
        except IOError as e:
            return
        except ValueError as e:
            raise ValueError("error parsing file %s: %s" % (f, str(e)))

    spt = None
    if support_macros:
        o("Parsing support macros (%s): " % support_macros)
        spt = refpolicy.SupportMacros()
        parse_file(support_macros, spt)

        headers.children.append(spt)

        # FIXME: Total hack - add in can_exec rather than parse the insanity
        # of misc_macros. We are just going to pretend that this is an interface
        # to make the expansion work correctly.
        can_exec = refpolicy.Interface("can_exec")
        av = access.AccessVector(["$1","$2","file","execute_no_trans","open", "read",
                                  "getattr","lock","execute","ioctl"])

        can_exec.children.append(refpolicy.AVRule(av))
        headers.children.append(can_exec)

        o("done.\n")

    if output and not debug:
        status = util.ConsoleProgressBar(sys.stdout, steps=len(modules))
        status.start("Parsing interface files")

    failures = []
    for x in modules:
        m = refpolicy.Module()
        m.name = x[0]
        try:
            if expand:
                parse_file(x[1], m, spt)
            else:
                parse_file(x[1], m)
        except ValueError as e:
            o(str(e) + "\n")
            failures.append(x[1])
            continue

        headers.children.append(m)
        if output and not debug:
            status.step()

    if len(failures):
        o("failed to parse some headers: %s\n" % ", ".join(failures))

    return headers
