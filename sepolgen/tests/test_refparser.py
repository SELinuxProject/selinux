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

import unittest
import sepolgen.refparser as refparser
import sepolgen.refpolicy as refpolicy

interface_example = """########################################
## <summary>
##	Search the content of /etc.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`files_search_usr',`
	gen_require(`
		type usr_t;
	')

	allow $1 usr_t:dir search;
        allow { domain $1 } { usr_t usr_home_t }:{ file dir } { read write getattr };
        typeattribute $1 file_type;

        if (foo) {
           allow $1 foo:bar baz;
        }

        if (bar) {
           allow $1 foo:bar baz;
        } else {
           allow $1 foo:bar baz;
        }
')

########################################
## <summary>
##	List the contents of generic
##	directories in /usr.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`files_list_usr',`
	gen_require(`
		type usr_t;
	')

	allow $1 usr_t:dir { read getattr };

        optional_policy(`
            search_usr($1)
        ')

        tunable_policy(`foo',`
            whatever($1)
        ')

')

########################################
## <summary>
##	Execute generic programs in /usr in the caller domain.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`files_exec_usr_files',`
	gen_require(`
		type usr_t;
	')

	allow $1 usr_t:dir read;
	allow $1 usr_t:lnk_file { read getattr };
	can_exec($1,usr_t)
        can_foo($1)

')
"""

class TestParser(unittest.TestCase):
    def test_interface_parsing(self):
        h = refparser.parse(interface_example)
        #print ""
        #refpolicy.print_tree(h)
        #self.assertEqual(len(h.interfaces), 3)

        name = "files_search_usr"
        #i = h.interfaces[name]
        #self.assertEqual(i.name, name)
        #self.assertEqual(len(i.rules), 1)
        #rule = i.rules[0]
        #self.assertTrue(isinstance(rule, refpolicy.AVRule))
        
                        
        
