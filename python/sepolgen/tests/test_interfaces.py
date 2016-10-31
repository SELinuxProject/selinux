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
import sepolgen.access as access
import sepolgen.interfaces as interfaces
import sepolgen.policygen as policygen
import sepolgen.refparser as refparser
import sepolgen.refpolicy as refpolicy

class TestParam(unittest.TestCase):
    def test(self):
        p = interfaces.Param()
        p.name = "$1"
        self.assertEqual(p.name, "$1")
        self.assertRaises(ValueError, p.set_name, "$N")
        self.assertEqual(p.num, 1)
        self.assertEqual(p.type, refpolicy.SRC_TYPE)

class TestAVExtractPerms(unittest.TestCase):
    def test(self):
        av = access.AccessVector(['foo', 'bar', 'file', 'read'])
        params = { }
        ret = interfaces.av_extract_params(av, params)
        self.assertEqual(ret, 0)
        self.assertEqual(params, { })

        av.src_type = "$1"
        ret = interfaces.av_extract_params(av, params)
        self.assertEqual(ret, 0)
        p = params["$1"]
        self.assertEqual(p.name, "$1")
        self.assertEqual(p.type, refpolicy.SRC_TYPE)
        self.assertEqual(p.obj_classes, refpolicy.IdSet(["file"]))

        params = { }
        av.tgt_type = "$1"
        av.obj_class = "process"
        ret = interfaces.av_extract_params(av, params)
        self.assertEqual(ret, 0) 
        p = params["$1"]
        self.assertEqual(p.name, "$1")
        self.assertEqual(p.type, refpolicy.SRC_TYPE)
        self.assertEqual(p.obj_classes, refpolicy.IdSet(["process"]))

        params = { }
        av.tgt_type = "$1"
        av.obj_class = "dir"
        ret = interfaces.av_extract_params(av, params)
        self.assertEqual(ret, 1) 
        p = params["$1"]
        self.assertEqual(p.name, "$1")
        self.assertEqual(p.type, refpolicy.SRC_TYPE)
        self.assertEqual(p.obj_classes, refpolicy.IdSet(["dir"]))

        av.src_type = "bar"
        av.tgt_type = "$2"
        av.obj_class = "dir"
        ret = interfaces.av_extract_params(av, params)
        self.assertEqual(ret, 0) 
        p = params["$2"]
        self.assertEqual(p.name, "$2")
        self.assertEqual(p.type, refpolicy.TGT_TYPE)
        self.assertEqual(p.obj_classes, refpolicy.IdSet(["dir"]))

interface_example = """
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

simple_interface = """
interface(`foo',`
   gen_require(`
       type usr_t;
   ')
   allow $1 usr_t:dir { create add_name };
   allow $1 usr_t:file { read write };
')
"""

test_expansion = """
interface(`foo',`
   gen_require(`
       type usr_t;
   ')
   allow $1 usr_t:dir { create add_name };
   allow $1 usr_t:file { read write };
')

interface(`map', `
   gen_require(`
       type bar_t;
   ')
   allow $1 bar_t:file read;
   allow $2 bar_t:file write;

   foo($2)
')

interface(`hard_map', `
   gen_require(`
      type baz_t;
   ')
   allow $1 baz_t:file getattr;
   allow $2 baz_t:file read;
   allow $3 baz_t:file write;

   map($1, $2)
   map($2, $3)

   # This should have no effect
   foo($2)
')
"""

def compare_avsets(l, avs_b):
    avs_a = access.AccessVectorSet()
    avs_a.from_list(l)

    a = list(avs_a)
    b = list(avs_b)

    a.sort()
    b.sort()

    if len(a) != len(b):
        return False


    for av_a, av_b in zip(a, b):
        if av_a != av_b:
            return False

    return True
        

class TestInterfaceSet(unittest.TestCase):
    def test_simple(self):
        h = refparser.parse(simple_interface)
        i = interfaces.InterfaceSet()
        i.add_headers(h)

        self.assertEqual(len(i.interfaces), 1)
        for key, interface in i.interfaces.items():
            self.assertEqual(key, interface.name)
            self.assertEqual(key, "foo")
            self.assertEqual(len(interface.access), 2)

            # Check the access vectors
            comp_avs = [["$1", "usr_t", "dir", "create", "add_name"],
                        ["$1", "usr_t", "file", "read", "write"]]
            ret = compare_avsets(comp_avs, interface.access)
            self.assertTrue(ret)

            # Check the params
            self.assertEqual(len(interface.params), 1)
            for param in interface.params.values():
                self.assertEqual(param.type, refpolicy.SRC_TYPE)
                self.assertEqual(param.name, "$1")
                self.assertEqual(param.num, 1)
                self.assertEqual(param.required, True)

    def test_expansion(self):
        h = refparser.parse(test_expansion)
        i = interfaces.InterfaceSet()
        i.add_headers(h)

        self.assertEqual(len(i.interfaces), 3)
        for key, interface in i.interfaces.items():
            self.assertEqual(key, interface.name)
            if key == "foo":
                comp_avs = [["$1", "usr_t", "dir", "create", "add_name"],
                            ["$1", "usr_t", "file", "read", "write"]]
                self.assertTrue(compare_avsets(comp_avs, interface.access))
            elif key == "map":
                comp_avs = [["$2", "usr_t", "dir", "create", "add_name"],
                            ["$2", "usr_t", "file", "read", "write"],
                            ["$1", "bar_t", "file", "read"],
                            ["$2", "bar_t", "file", "write"]]
                self.assertTrue(compare_avsets(comp_avs, interface.access))
            elif key == "hard_map":
                comp_avs = [["$1", "baz_t", "file", "getattr"],
                            ["$2", "baz_t", "file", "read"],
                            ["$3", "baz_t", "file", "write"],
                            
                            ["$2", "usr_t", "dir", "create", "add_name"],
                            ["$2", "usr_t", "file", "read", "write"],
                            ["$1", "bar_t", "file", "read"],
                            ["$2", "bar_t", "file", "write"],
                            
                            ["$3", "usr_t", "dir", "create", "add_name"],
                            ["$3", "usr_t", "file", "read", "write"],
                            ["$2", "bar_t", "file", "read"],
                            ["$3", "bar_t", "file", "write"]]
                self.assertTrue(compare_avsets(comp_avs, interface.access))
                
        
    def test_export(self):
        h = refparser.parse(interface_example)
        i = interfaces.InterfaceSet()
        i.add_headers(h)
        f = open("output", "w")
        i.to_file(f)
        f.close()

        i2 = interfaces.InterfaceSet()
        f = open("output")
        i2.from_file(f)
        f.close()
        if_status = [False, False, False]
        for ifv in i2.interfaces.values():
            if ifv.name == "files_search_usr":
                if_status[0] = True
            if ifv.name == "files_list_usr":
                if_status[1] = True
            if ifv.name == "files_exec_usr_files":
                if_status[2] = True

        self.assertEqual(if_status[0], True)
        self.assertEqual(if_status[1], True)
        self.assertEqual(if_status[2], True)
