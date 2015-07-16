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
import sys

tokens = ('DEFINE',
          'NAME',
          'TICK',
          'SQUOTE',
          'OBRACE',
          'CBRACE',
          'SEMI',
          'OPAREN',
          'CPAREN',
          'COMMA')

reserved = {
    'define' : 'DEFINE' }

t_TICK      = r'\`'
t_SQUOTE    = r'\''
t_OBRACE    = r'\{'
t_CBRACE    = r'\}'
t_SEMI      = r'\;'
t_OPAREN    = r'\('
t_CPAREN    = r'\)'
t_COMMA     = r'\,'

t_ignore    = " \t\n"

def t_NAME(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value,'NAME')
    return t

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.skip(1)

from . import lex
lex.lex()

def p_statements(p):
    '''statements : define_stmt
                  | define_stmt statements
    '''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + [p[2]]

def p_define_stmt(p):
    # This sucks - corresponds to 'define(`foo',`{ read write }')
    '''define_stmt : DEFINE OPAREN TICK NAME SQUOTE COMMA TICK list SQUOTE CPAREN
    '''
    
    p[0] = [p[4], p[8]]

def p_list(p):
    '''list : NAME
            | OBRACE names CBRACE
    '''
    if p[1] == "{":
        p[0] = p[2]
    else:
        p[0] = [p[1]]

def p_names(p):
    '''names : NAME
             | NAME names
    '''
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = [p[1]] + p[2]

def p_error(p):
    print("Syntax error on line %d %s [type=%s]" % (p.lineno, p.value, p.type))
    
from . import yacc
yacc.yacc()


f = open("all_perms.spt")
txt = f.read()
f.close()

#lex.input(txt)
#while 1:
#    tok = lex.token()
#    if not tok:
#        break
#    print tok

test = "define(`foo',`{ read write append }')"
test2 = """define(`all_filesystem_perms',`{ mount remount unmount getattr relabelfrom relabelto transition associate quotamod quotaget }')
define(`all_security_perms',`{ compute_av compute_create compute_member check_context load_policy compute_relabel compute_user setenforce setbool setsecparam setcheckreqprot }')
"""
result = yacc.parse(txt)
print(result)
    
