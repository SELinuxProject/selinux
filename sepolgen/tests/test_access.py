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
import sepolgen.refparser as refparser
import sepolgen.policygen as policygen
import sepolgen.access as access

class TestAccessVector(unittest.TestCase):
    def test_init(self):
        # Default construction
        a = access.AccessVector()
        self.assertEqual(a.src_type, None)
        self.assertEqual(a.tgt_type, None)
        self.assertEqual(a.obj_class, None)
        self.assertTrue(isinstance(a.perms, refpolicy.IdSet))
        self.assertTrue(isinstance(a.audit_msgs, type([])))
        self.assertEquals(len(a.audit_msgs), 0)

        # Construction from a list
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        l = access.AccessVector(['foo', 'bar', 'file', 'read', 'write'])
        self.assertEqual(a.src_type, l.src_type)
        self.assertEqual(a.tgt_type, l.tgt_type)
        self.assertEqual(a.obj_class, l.obj_class)
        self.assertEqual(a.perms, l.perms)

    def test_from_list(self):
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        l = access.AccessVector()
        l.from_list(['foo', 'bar', 'file', 'read', 'write'])
        self.assertEqual(a.src_type, l.src_type)
        self.assertEqual(a.tgt_type, l.tgt_type)
        self.assertEqual(a.obj_class, l.obj_class)
        self.assertEqual(a.perms, l.perms)

    def test_to_list(self):
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        l = a.to_list()
        self.assertEqual(l[0], "foo")
        self.assertEqual(l[1], "bar")
        self.assertEqual(l[2], "file")
        self.assertEqual(l[3], "read")
        self.assertEqual(l[4], "write")

    def test_to_string(self):
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        self.assertEquals(str(a), "allow foo bar:file { read write };")
        self.assertEquals(a.to_string(), "allow foo bar:file { read write };")

    def test_cmp(self):
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        b = access.AccessVector()
        b.src_type = "foo"
        b.tgt_type = "bar"
        b.obj_class = "file"
        b.perms.update(["read", "write"])

        self.assertEquals(a, b)

        # Source Type
        b.src_type = "baz"
        self.assertEquals(cmp(a, b), 1)

        b.src_type = "gaz"
        self.assertEquals(cmp(a, b), -1)

        # Target Type
        b.src_type = "foo"
        b.tgt_type = "aar"
        self.assertEquals(cmp(a, b), 1)

        b.tgt_type = "gaz"
        self.assertEquals(cmp(a, b), -1)

        # Perms
        b.tgt_type = "bar"
        b.perms = refpolicy.IdSet(["read"])
        ret = cmp(a, b)
        self.assertEquals(ret, 1)

        b.perms = refpolicy.IdSet(["read", "write", "append"])
        ret = cmp(a, b)
        self.assertEquals(ret, -1)

        b.perms = refpolicy.IdSet(["read", "append"])
        ret = cmp(a, b)
        self.assertEquals(ret, 1)
                         
class TestUtilFunctions(unittest.TestCase):
    def test_is_idparam(self):
        self.assertTrue(access.is_idparam("$1"))
        self.assertTrue(access.is_idparam("$2"))
        self.assertTrue(access.is_idparam("$123"))
        self.assertFalse(access.is_idparam("$123.23"))
        self.assertFalse(access.is_idparam("$A"))

    def test_avrule_to_access_vectors(self):
        rule = refpolicy.AVRule()
        rule.src_types.add("foo")
        rule.src_types.add("baz")
        rule.tgt_types.add("bar")
        rule.tgt_types.add("what")
        rule.obj_classes.add("file")
        rule.obj_classes.add("dir")
        rule.perms.add("read")
        rule.perms.add("write")

        avs = access.avrule_to_access_vectors(rule)
        self.assertEquals(len(avs), 8)
        comps = [("foo", "what", "dir"),
                 ("foo", "what", "file"),
                 ("foo", "bar", "dir"),
                 ("foo", "bar", "file"),
                 ("baz", "what", "dir"),
                 ("baz", "what", "file"),
                 ("baz", "bar", "dir"),
                 ("baz", "bar", "file")]
        status = [False] * 8
        for av in access.avrule_to_access_vectors(rule):
            self.assertEquals(av.perms, refpolicy.IdSet(["read", "write"]))
            for i in xrange(len(comps)):
                if comps[i][0] == av.src_type and \
                   comps[i][1] == av.tgt_type and \
                   comps[i][2] == av.obj_class:
                    status[i] = True

        for s in status:
            self.assertEquals(s, True)
                   

class TestAccessVectorSet(unittest.TestCase):
    def setUp(self):
        rule = refpolicy.AVRule()
        rule.src_types.add("foo")
        rule.src_types.add("baz")
        rule.tgt_types.add("bar")
        rule.tgt_types.add("what")
        rule.obj_classes.add("file")
        rule.obj_classes.add("dir")
        rule.perms.add("read")
        rule.perms.add("write")

        s = access.AccessVectorSet()
        avs = access.avrule_to_access_vectors(rule)
        for av in avs:
            s.add_av(av)
        self.s = s
    
    def test_init(self):
        a = access.AccessVectorSet()

    def test_iter(self):
        comps = [("foo", "what", "dir"),
                 ("foo", "what", "file"),
                 ("foo", "bar", "dir"),
                 ("foo", "bar", "file"),
                 ("baz", "what", "dir"),
                 ("baz", "what", "file"),
                 ("baz", "bar", "dir"),
                 ("baz", "bar", "file")]
        status = [False] * 8
        for av in self.s:
            self.assertEquals(av.perms, refpolicy.IdSet(["read", "write"]))
            for i in xrange(len(comps)):
                if comps[i][0] == av.src_type and \
                   comps[i][1] == av.tgt_type and \
                   comps[i][2] == av.obj_class:
                    status[i] = True

        for s in status:
            self.assertEquals(s, True)

    def test_len(self):
        self.assertEquals(len(self.s), 8)

    def test_list(self):
        a = access.AccessVectorSet()
        a.add("$1", "foo", "file", refpolicy.IdSet(["read", "write"]))
        a.add("$1", "bar", "file", refpolicy.IdSet(["read", "write"]))
        a.add("what", "bar", "file", refpolicy.IdSet(["read", "write"]))

        avl = a.to_list()

        test_l = [['what','bar','file','read','write'],
                  ['$1','foo','file','read','write'],
                  ['$1','bar','file','read','write']]

        for a,b in zip(test_l, avl):
            self.assertEqual(len(a), len(b))
            for x,y in zip(a,b):
                self.assertEqual(x, y)
                
        b = access.AccessVectorSet()
        b.from_list(avl)
        self.assertEqual(len(b), 3)
