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
        self.assertTrue(isinstance(a.xperms, type({})))
        self.assertEqual(len(a.audit_msgs), 0)

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

        l2 = access.AccessVector()
        with self.assertRaises(ValueError):
            l2.from_list(['foo', 'bar', 'file'])

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
        perms = l[3:]
        perms.sort()
        self.assertEqual(perms[0], "read")
        self.assertEqual(perms[1], "write")

    def test_to_string(self):
        a = access.AccessVector()
        a.src_type = "foo"
        a.tgt_type = "bar"
        a.obj_class = "file"
        a.perms.update(["read", "write"])

        first, second = str(a).split(':')
        self.assertEqual(first, "allow foo bar")
        second = second.split(' ')
        second.sort()
        expected = "file { read write };".split(' ')
        expected.sort()
        self.assertEqual(second, expected)

        first, second = a.to_string().split(':')
        self.assertEqual(first, "allow foo bar")
        second = second.split(' ')
        second.sort()
        expected = "file { read write };".split(' ')
        expected.sort()
        self.assertEqual(second, expected)

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

        self.assertEqual(a, b)

        # Source Type
        b.src_type = "baz"
        self.assertNotEqual(a, b)
        self.assertTrue(a > b)

        b.src_type = "gaz"
        self.assertNotEqual(a, b)
        self.assertTrue(a < b)

        # Target Type
        b.src_type = "foo"
        b.tgt_type = "aar"
        self.assertNotEqual(a, b)
        self.assertTrue(a > b)

        b.tgt_type = "gaz"
        self.assertNotEqual(a, b)
        self.assertTrue(a < b)

        # Perms
        b.tgt_type = "bar"
        b.perms = refpolicy.IdSet(["read"])
        self.assertNotEqual(a, b)
        self.assertTrue(a > b)

        b.perms = refpolicy.IdSet(["read", "write", "append"])
        self.assertNotEqual(a, b)

        b.perms = refpolicy.IdSet(["read", "append"])
        self.assertNotEqual(a, b)

    def test_merge_noxperm(self):
        """Test merging two AVs without xperms"""
        a = access.AccessVector(["foo", "bar", "file", "read", "write"])
        b = access.AccessVector(["foo", "bar", "file", "append"])

        a.merge(b)
        self.assertEqual(sorted(list(a.perms)), ["append", "read", "write"])

    def text_merge_xperm1(self):
        """Test merging AV that contains xperms with AV that does not"""
        a = access.AccessVector(["foo", "bar", "file", "read"])
        b = access.AccessVector(["foo", "bar", "file", "read"])
        xp = refpolicy.XpermSet()
        xp.add(42)
        xp.add(12345)
        b.xperms = {"ioctl": xp}

        a.merge(b)
        self.assertEqual(sorted(list(a.perms)), ["append", "read", "write"])
        self.assertEqual(list(a.xperms.keys()), ["ioctl"])
        self.assertEqual(a.xperms["ioctl"].to_string(), "{ 0x2a 0x3039 }")

    def text_merge_xperm2(self):
        """Test merging AV that does not contain xperms with AV that does"""
        a = access.AccessVector(["foo", "bar", "file", "read"])
        xp = refpolicy.XpermSet()
        xp.add(42)
        xp.add(12345)
        a.xperms = {"ioctl": xp}
        b = access.AccessVector(["foo", "bar", "file", "read"])

        a.merge(b)
        self.assertEqual(sorted(list(a.perms)), ["append", "read", "write"])
        self.assertEqual(list(a.xperms.keys()), ["ioctl"])
        self.assertEqual(a.xperms["ioctl"].to_string(), "{ 0x2a 0x3039 }")

    def test_merge_xperm_diff_op(self):
        """Test merging two AVs that contain xperms with different operation"""
        a = access.AccessVector(["foo", "bar", "file", "read"])
        xp1 = refpolicy.XpermSet()
        xp1.add(23)
        a.xperms = {"asdf": xp1}

        b = access.AccessVector(["foo", "bar", "file", "read"])
        xp2 = refpolicy.XpermSet()
        xp2.add(42)
        xp2.add(12345)
        b.xperms = {"ioctl": xp2}

        a.merge(b)
        self.assertEqual(list(a.perms), ["read"])
        self.assertEqual(sorted(list(a.xperms.keys())), ["asdf", "ioctl"])
        self.assertEqual(a.xperms["asdf"].to_string(), "0x17")
        self.assertEqual(a.xperms["ioctl"].to_string(), "{ 0x2a 0x3039 }")
                         
    def test_merge_xperm_same_op(self):
        """Test merging two AVs that contain xperms with same operation"""
        a = access.AccessVector(["foo", "bar", "file", "read"])
        xp1 = refpolicy.XpermSet()
        xp1.add(23)
        a.xperms = {"ioctl": xp1}

        b = access.AccessVector(["foo", "bar", "file", "read"])
        xp2 = refpolicy.XpermSet()
        xp2.add(42)
        xp2.add(12345)
        b.xperms = {"ioctl": xp2}

        a.merge(b)
        self.assertEqual(list(a.perms), ["read"])
        self.assertEqual(list(a.xperms.keys()), ["ioctl"])
        self.assertEqual(a.xperms["ioctl"].to_string(), "{ 0x17 0x2a 0x3039 }")

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
        self.assertEqual(len(avs), 8)
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
            self.assertEqual(av.perms, refpolicy.IdSet(["read", "write"]))
            for i in range(len(comps)):
                if comps[i][0] == av.src_type and \
                   comps[i][1] == av.tgt_type and \
                   comps[i][2] == av.obj_class:
                    status[i] = True

        for s in status:
            self.assertEqual(s, True)
                   

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
            self.assertEqual(av.perms, refpolicy.IdSet(["read", "write"]))
            for i in range(len(comps)):
                if comps[i][0] == av.src_type and \
                   comps[i][1] == av.tgt_type and \
                   comps[i][2] == av.obj_class:
                    status[i] = True

        for s in status:
            self.assertEqual(s, True)

    def test_len(self):
        self.assertEqual(len(self.s), 8)

    def test_list(self):
        a = access.AccessVectorSet()
        a.add("$1", "foo", "file", refpolicy.IdSet(["read", "write"]))
        a.add("$1", "bar", "file", refpolicy.IdSet(["read", "write"]))
        a.add("what", "bar", "file", refpolicy.IdSet(["read", "write"]))

        avl = a.to_list()
        avl.sort()

        test_l = [['what','bar','file','read','write'],
                  ['$1','foo','file','read','write'],
                  ['$1','bar','file','read','write']]
        test_l.sort()

        for a,b in zip(test_l, avl):
            self.assertEqual(len(a), len(b))
            for x,y in list(zip(a,b))[:3]:
                self.assertEqual(x, y)
            perms1 = a[3:]
            perms2 = b[3:]
            perms1.sort()
            perms2.sort()
            self.assertEqual(perms1, perms2)
                
        b = access.AccessVectorSet()
        b.from_list(avl)
        self.assertEqual(len(b), 3)

    def test_add_av_first(self):
        """Test adding first AV to the AV set"""
        avs = access.AccessVectorSet()
        av = access.AccessVector(['foo', 'bar', 'file', 'read'])

        avs.add_av(av)

        self.assertEqual(avs.to_list(), [['foo', 'bar', 'file', 'read']])

    def test_add_av_second(self):
        """Test adding second AV to the AV set with same source and target
        context and class"""
        avs = access.AccessVectorSet()
        av1 = access.AccessVector(['foo', 'bar', 'file', 'read'])
        av2 = access.AccessVector(['foo', 'bar', 'file', 'write'])

        avs.add_av(av1)
        avs.add_av(av2)

        self.assertEqual(avs.to_list(), [['foo', 'bar', 'file', 'read',
                         'write']])

    def test_add_av_with_msg(self):
        """Test adding audit message"""
        avs = access.AccessVectorSet()
        av = access.AccessVector(['foo', 'bar', 'file', 'read'])

        avs.add_av(av, 'test message')

        self.assertEqual(avs.src['foo']['bar']['file', av.type].audit_msgs,
                         ['test message'])

    def test_add(self):
        """Test adding AV to the set"""
        s = access.AccessVectorSet()

        def test_add_av(av, audit_msg=None):
            self.assertEqual(av.src_type, 'foo')
            self.assertEqual(av.tgt_type, 'bar')
            self.assertEqual(av.obj_class, 'file')
            self.assertEqual(list(av.perms), ['read'])
            self.assertEqual(av.data, 'test data')
            self.assertEqual(av.type, 42)
            self.assertEqual(audit_msg, 'test message')

        s.add_av = test_add_av

        s.add("foo", "bar", "file", refpolicy.IdSet(["read"]),
              audit_msg='test message', avc_type=42, data='test data')
