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
import sepolgen.objectmodel

class TestInfoFlow(unittest.TestCase):
    def test_from_file(self):
        info = sepolgen.objectmodel.PermMappings()
        fd = open("perm_map")
        info.from_file(fd)
        fd.close()

        pm = info.get("filesystem", "mount")
        self.assertEqual(pm.perm, "mount")
        self.assertEqual(pm.dir, sepolgen.objectmodel.FLOW_WRITE)
        self.assertEqual(pm.weight, 1)

        self.assertRaises(KeyError, info.get, "filesystem", "foo")

        pm = info.getdefault("filesystem", "foo")
        self.assertEqual(pm.perm, "foo")
        self.assertEqual(pm.dir, sepolgen.objectmodel.FLOW_BOTH)
        self.assertEqual(pm.weight, 5)

        pm = info.getdefault("foo", "bar")
        self.assertEqual(pm.perm, "bar")
        self.assertEqual(pm.dir, sepolgen.objectmodel.FLOW_BOTH)
        self.assertEqual(pm.weight, 5)
