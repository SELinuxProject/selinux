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

"""
Utilities for dealing with the compilation of modules and creation
of module tress.
"""

import re
import tempfile
try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput
import os
import os.path
import shutil

import selinux

from . import defaults


def is_valid_name(modname):
    """Check that a module name is valid.
    """
    m = re.findall(r"[^a-zA-Z0-9_\-\.]", modname)
    if len(m) == 0 and modname[0].isalpha():
        return True
    else:
        return False

class ModuleTree:
    def __init__(self, modname):
        self.modname = modname
        self.dirname = None

    def dir_name(self):
        return self.dirname

    def te_name(self):
        return self.dirname + "/" + self.modname + ".te"

    def fc_name(self):
        return self.dirname + "/" + self.modname + ".fc"

    def if_name(self):
        return self.dirname + "/" + self.modname + ".if"

    def package_name(self):
        return self.dirname + "/" + self.modname + ".pp"

    def makefile_name(self):
        return self.dirname + "/Makefile"

    def create(self, parent_dirname, makefile_include=None):
        self.dirname = parent_dirname + "/" + self.modname
        os.mkdir(self.dirname)
        fd = open(self.makefile_name(), "w")
        if makefile_include:
            fd.write("include " + makefile_include)
        else:
            fd.write("include " + defaults.refpolicy_makefile())
        fd.close()

        # Create empty files for the standard refpolicy
        # module files
        open(self.te_name(), "w").close()
        open(self.fc_name(), "w").close()
        open(self.if_name(), "w").close()

def modname_from_sourcename(sourcename):
    return os.path.splitext(os.path.split(sourcename)[1])[0]

class ModuleCompiler:
    """ModuleCompiler eases running of the module compiler.

    The ModuleCompiler class encapsulates running the commandline
    module compiler (checkmodule) and module packager (semodule_package).
    You are likely interested in the create_module_package method.
    
    Several options are controlled via parameters (only effects the
    non-refpol builds):
    
     .mls          [boolean] Generate an MLS module (by passed -M to
                   checkmodule). True to generate an MLS module, false
                   otherwise.
                   
     .module       [boolean] Generate a module instead of a base module.
                   True to generate a module, false to generate a base.
                   
     .checkmodule  [string] Fully qualified path to the module compiler.
                   Default is /usr/bin/checkmodule.
                   
     .semodule_package [string] Fully qualified path to the module
                   packager. Defaults to /usr/bin/semodule_package.
     .output       [file object] File object used to write verbose
                   output of the compilation and packaging process.
    """
    def __init__(self, output=None):
        """Create a ModuleCompiler instance, optionally with an
        output file object for verbose output of the compilation process.
        """
        self.mls = selinux.is_selinux_mls_enabled()
        self.module = True
        self.checkmodule = "/usr/bin/checkmodule"
        self.semodule_package = "/usr/bin/semodule_package"
        self.output = output
        self.last_output = ""
        self.refpol_makefile = defaults.refpolicy_makefile()
        self.make = "/usr/bin/make"

    def o(self, str):
        if self.output:
            self.output.write(str + "\n")
        self.last_output = str

    def run(self, command):
        self.o(command)
        rc, output = getstatusoutput(command)
        self.o(output)
        
        return rc
    
    def gen_filenames(self, sourcename):
        """Generate the module and policy package filenames from
        a source file name. The source file must be in the form
        of "foo.te". This will generate "foo.mod" and "foo.pp".
        
        Returns a tuple with (modname, policypackage).
        """
        splitname = sourcename.split(".")
        if len(splitname) < 2:
            raise RuntimeError("invalid sourcefile name %s (must end in .te)", sourcename)
        # Handle other periods in the filename correctly
        basename = ".".join(splitname[0:-1])
        modname = basename + ".mod"
        packagename = basename + ".pp"
        
        return (modname, packagename)

    def create_module_package(self, sourcename, refpolicy=True):
        """Create a module package saved in a packagename from a
        sourcename.

        The create_module_package creates a module package saved in a
        file named sourcename (.pp is the standard extension) from a
        source file (.te is the standard extension). The source file
        should contain SELinux policy statements appropriate for a
        base or non-base module (depending on the setting of .module).

        Only file names are accepted, not open file objects or
        descriptors because the command line SELinux tools are used.

        On error a RuntimeError will be raised with a descriptive
        error message.
        """
        if refpolicy:
            self.refpol_build(sourcename)
        else:
            modname, packagename = self.gen_filenames(sourcename)
            self.compile(sourcename, modname)
            self.package(modname, packagename)
            os.unlink(modname)
            
    def refpol_build(self, sourcename):
        # Compile
        command = self.make + " -f " + self.refpol_makefile
        rc = self.run(command)

        # Raise an error if the process failed
        if rc != 0:
            raise RuntimeError("compilation failed:\n%s" % self.last_output)
        
    def compile(self, sourcename, modname):
        s = [self.checkmodule]
        if self.mls:
            s.append("-M")
        if self.module:
            s.append("-m")
        s.append("-o")
        s.append(modname)
        s.append(sourcename)

        rc = self.run(" ".join(s))
        if rc != 0:
            raise RuntimeError("compilation failed:\n%s" % self.last_output)

    def package(self, modname, packagename):
        s = [self.semodule_package]
        s.append("-o")
        s.append(packagename)
        s.append("-m")
        s.append(modname)
        
        rc = self.run(" ".join(s))
        if rc != 0:
            raise RuntimeError("packaging failed [%s]" % self.last_output)
        
    
