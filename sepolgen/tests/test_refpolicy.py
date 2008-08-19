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
import sepolgen.refpolicy as refpolicy
import selinux

class TestIdSet(unittest.TestCase):
    def test_set_to_str(self):
        s = refpolicy.IdSet(["read", "write", "getattr"])
        self.assertEquals(s.to_space_str(), "{ read write getattr }")
        s = refpolicy.IdSet()
        s.add("read")
        self.assertEquals(s.to_space_str(), "read")

class TestSecurityContext(unittest.TestCase):
    def test_init(self):
        sc = refpolicy.SecurityContext()
        sc = refpolicy.SecurityContext("user_u:object_r:foo_t")
    
    def test_from_string(self):
        context = "user_u:object_r:foo_t"
        sc = refpolicy.SecurityContext()
        sc.from_string(context)
        self.assertEquals(sc.user, "user_u")
        self.assertEquals(sc.role, "object_r")
        self.assertEquals(sc.type, "foo_t")
        self.assertEquals(sc.level, None)
        if selinux.is_selinux_mls_enabled():
            self.assertEquals(str(sc), context + ":s0")
        else:
            self.assertEquals(str(sc), context)
        self.assertEquals(sc.to_string(default_level="s1"), context + ":s1")

        context = "user_u:object_r:foo_t:s0-s0:c0-c255"
        sc = refpolicy.SecurityContext()
        sc.from_string(context)
        self.assertEquals(sc.user, "user_u")
        self.assertEquals(sc.role, "object_r")
        self.assertEquals(sc.type, "foo_t")
        self.assertEquals(sc.level, "s0-s0:c0-c255")
        self.assertEquals(str(sc), context)
        self.assertEquals(sc.to_string(), context)

        sc = refpolicy.SecurityContext()
        self.assertRaises(ValueError, sc.from_string, "abc")

    def test_equal(self):
        sc1 = refpolicy.SecurityContext("user_u:object_r:foo_t")
        sc2 = refpolicy.SecurityContext("user_u:object_r:foo_t")
        sc3 = refpolicy.SecurityContext("user_u:object_r:foo_t:s0")
        sc4 = refpolicy.SecurityContext("user_u:object_r:bar_t")

        self.assertEquals(sc1, sc2)
        self.assertNotEquals(sc1, sc3)
        self.assertNotEquals(sc1, sc4)

class TestObjecClass(unittest.TestCase):
    def test_init(self):
        o = refpolicy.ObjectClass(name="file")
        self.assertEquals(o.name, "file")
        self.assertTrue(isinstance(o.perms, set))

class TestAVRule(unittest.TestCase):
    def test_init(self):
        a = refpolicy.AVRule()
        self.assertEquals(a.rule_type, a.ALLOW)
        self.assertTrue(isinstance(a.src_types, set))
        self.assertTrue(isinstance(a.tgt_types, set))
        self.assertTrue(isinstance(a.obj_classes, set))
        self.assertTrue(isinstance(a.perms, set))

    def test_to_string(self):
        a = refpolicy.AVRule()
        a.src_types.add("foo_t")
        a.tgt_types.add("bar_t")
        a.obj_classes.add("file")
        a.perms.add("read")
        self.assertEquals(a.to_string(), "allow foo_t bar_t:file read;")

        a.rule_type = a.DONTAUDIT
        a.src_types.add("user_t")
        a.tgt_types.add("user_home_t")
        a.obj_classes.add("lnk_file")
        a.perms.add("write")
        # This test might need to go because set ordering is not guaranteed
        self.assertEquals(a.to_string(),
                          "dontaudit { foo_t user_t } { user_home_t bar_t }:{ lnk_file file } { read write };")

class TestTypeRule(unittest.TestCase):
    def test_init(self):
        a = refpolicy.TypeRule()
        self.assertEquals(a.rule_type, a.TYPE_TRANSITION)
        self.assertTrue(isinstance(a.src_types, set))
        self.assertTrue(isinstance(a.tgt_types, set))
        self.assertTrue(isinstance(a.obj_classes, set))
        self.assertEquals(a.dest_type, "")

    def test_to_string(self):
        a = refpolicy.TypeRule()
        a.src_types.add("foo_t")
        a.tgt_types.add("bar_exec_t")
        a.obj_classes.add("process")
        a.dest_type = "bar_t"
        self.assertEquals(a.to_string(), "type_transition foo_t bar_exec_t:process bar_t;")


class TestParseNode(unittest.TestCase):
    def test_walktree(self):
        # Construct a small tree
        h = refpolicy.Headers()
        a = refpolicy.AVRule()
        a.src_types.add("foo_t")
        a.tgt_types.add("bar_t")
        a.obj_classes.add("file")
        a.perms.add("read")

        ifcall = refpolicy.InterfaceCall(ifname="allow_foobar")
        ifcall.args.append("foo_t")
        ifcall.args.append("{ file dir }")

        i = refpolicy.Interface(name="foo")
        i.children.append(a)
        i.children.append(ifcall)
        h.children.append(i)

        a = refpolicy.AVRule()
        a.rule_type = a.DONTAUDIT
        a.src_types.add("user_t")
        a.tgt_types.add("user_home_t")
        a.obj_classes.add("lnk_file")
        a.perms.add("write")
        i = refpolicy.Interface(name="bar")
        i.children.append(a)
        h.children.append(i)

class TestHeaders(unittest.TestCase):
    def test_iter(self):
        h = refpolicy.Headers()
        h.children.append(refpolicy.Interface(name="foo"))
        h.children.append(refpolicy.Interface(name="bar"))
        h.children.append(refpolicy.ClassMap("file", "read write"))
        i = 0
        for node in h:
            i += 1
        self.assertEqual(i, 3)
        
        i = 0
        for node in h.interfaces():
            i += 1
        self.assertEqual(i, 2)
        
