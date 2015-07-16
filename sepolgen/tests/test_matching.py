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
import sepolgen.matching as matching
import sepolgen.refparser as refparser
import sepolgen.interfaces as interfaces
import sepolgen.access as access

class TestMatch(unittest.TestCase):
    def test(self):
        a = matching.Match()
        a.dist = 100
        a.info_dir_change = True

        b = matching.Match()
        b.dist = 100
        b.info_dir_change = True

        self.assertEqual(a, b)
        b.info_dir_change = False
        self.assertTrue((a > b))
        self.assertTrue((b < a))

        b.dist = 200

        self.assertTrue((a < b))
        self.assertTrue((b > a))

class TestMatchList(unittest.TestCase):
    def test_append(self):
        ml = matching.MatchList()
        ml.threshold = 100

        a = matching.Match()
        a.dist = 100
        ml.append(a)
        self.assertEqual(len(ml), 1)

        a = matching.Match()
        a.dist = 200
        ml.append(a)
        self.assertEqual(len(ml), 2)
        self.assertEqual(len(ml.bastards), 1)

        ml.allow_info_dir_change = False
        a = matching.Match()
        a.dist = 0
        a.info_dir_change = True
        ml.append(a)
        self.assertEqual(len(ml), 3)
        self.assertEqual(len(ml.bastards), 2)

    def test_sort(self):
        ml = matching.MatchList()
        ml.threshold = 100

        a = matching.Match()
        a.dist = 100
        ml.append(a)

        b = matching.Match()
        b.dist = 5
        ml.append(b)

        c = matching.Match()
        c.dist = 0
        ml.append(c)

        l = [c, b, a]

        ml.sort()

        for x, y in zip(l, ml):
            self.assertEqual(x, y)

        self.assertEqual(ml.best(), c)


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

class AccessMatcher(unittest.TestCase):
    def test_search(self):
        h = refparser.parse(test_expansion)
        i = interfaces.InterfaceSet()
        i.add_headers(h)

        a = access.AccessVector(["foo_t", "usr_t", "dir", "create"])
        m = matching.AccessMatcher()
        ml = matching.MatchList()

        ans = m.search_ifs(i, a, ml)
                
        
        pass
