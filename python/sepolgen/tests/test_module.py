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
import sepolgen.module as module
import os

class TestModuleCompiler(unittest.TestCase):
    def test(self):
        package = "module_compile_test.pp"
        mc = module.ModuleCompiler()
        mc.create_module_package("module_compile_test.te", refpolicy=True)
        os.stat(package)
        os.unlink(package)

        mc.refpolicy = True
        mc.create_module_package("module_compile_test.te", refpolicy=False)
        os.stat(package)
        os.unlink(package)
