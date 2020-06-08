# Copyright (C) 2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# policygentool is a tool for the initial generation of SELinux policy
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#                                        02111-1307  USA
#
#
import re
import sys
import sepolicy
ADMIN_TRANSITION_INTERFACE = "_admin$"
USER_TRANSITION_INTERFACE = "_role$"

__all__ = ['get_all_interfaces', 'get_interfaces_from_xml', 'get_admin', 'get_user', 'get_interface_dict', 'get_interface_format_text', 'get_interface_compile_format_text', 'get_xml_file', 'interface_compile_test']

##
## I18N
##
PROGNAME = "policycoreutils"
try:
    import gettext
    kwargs = {}
    if sys.version_info < (3,):
        kwargs['unicode'] = True
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    codeset='utf-8',
                    **kwargs)
except:
    try:
        import builtins
        builtins.__dict__['_'] = str
    except ImportError:
        import __builtin__
        __builtin__.__dict__['_'] = unicode


def get_interfaces_from_xml(path):
    """ Get all interfaces from given xml file"""
    interfaces_list = []
    idict = get_interface_dict(path)
    for k in idict.keys():
        interfaces_list.append(k)
    return interfaces_list


def get_all_interfaces(path=""):
    from sepolicy import get_methods
    all_interfaces = []
    if not path:
        all_interfaces = get_methods()
    else:
        xml_path = get_xml_file(path)
        all_interfaces = get_interfaces_from_xml(xml_path)

    return all_interfaces


def get_admin(path=""):
    """ Get all domains with an admin interface from installed policy."""
    """ If xml_path is specified, func returns an admin interface from specified xml file"""
    admin_list = []
    if path:
        try:
            xml_path = get_xml_file(path)
            idict = get_interface_dict(xml_path)
            for k in idict.keys():
                if k.endswith("_admin"):
                    admin_list.append(k)
        except IOError as e:
            sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
            sys.exit(1)
    else:
        for i in sepolicy.get_methods():
            if i.endswith("_admin"):
                admin_list.append(i.split("_admin")[0])

    return admin_list


def get_user(path=""):
    """ Get all domains with SELinux user role interface"""
    """ If xml_path is specified, func returns an user role interface from specified xml file"""
    trans_list = []
    if path:
        try:
            xml_path = get_xml_file(path)
            idict = get_interface_dict(xml_path)
            for k in idict.keys():
                if k.endswith("_role"):
                    if (("%s_exec_t" % k[:-5]) in sepolicy.get_all_types()):
                        trans_list.append(k)
        except IOError as e:
            sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
            sys.exit(1)
    else:
        for i in sepolicy.get_methods():
            m = re.findall("(.*)%s" % USER_TRANSITION_INTERFACE, i)
            if len(m) > 0:
                if "%s_exec_t" % m[0] in sepolicy.get_all_types():
                    trans_list.append(m[0])

    return trans_list

interface_dict = None


def get_interface_dict(path="/usr/share/selinux/devel/policy.xml"):
    global interface_dict
    import os
    import xml.etree.ElementTree
    if interface_dict:
        return interface_dict

    interface_dict = {}
    param_list = []

    xml_path = """<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?>
<policy>
<layer name="admin">
"""
    xml_path += path
    xml_path += """
</layer>
</policy>
"""

    try:
        if os.path.isfile(path):
            tree = xml.etree.ElementTree.parse(path)
        else:
            tree = xml.etree.ElementTree.fromstring(xml_path)
        for l in tree.findall("layer"):
            for m in l.findall("module"):
                for i in m.iter('interface'):
                    for e in i.findall("param"):
                        param_list.append(e.get('name'))
                    interface_dict[(i.get("name"))] = [param_list, (i.find('summary').text), "interface"]
                    param_list = []
                for i in m.iter('template'):
                    for e in i.findall("param"):
                        param_list.append(e.get('name'))
                    interface_dict[(i.get("name"))] = [param_list, (i.find('summary').text), "template"]
                    param_list = []
    except IOError:
        pass
    return interface_dict


def get_interface_format_text(interface, path="/usr/share/selinux/devel/policy.xml"):
    idict = get_interface_dict(path)
    interface_text = "%s(%s) %s" % (interface, ", ".join(idict[interface][0]), " ".join(idict[interface][1].split("\n")))

    return interface_text


def get_interface_compile_format_text(interfaces_dict, interface):
    from .templates import test_module
    param_tmp = []
    for i in interfaces_dict[interface][0]:
        param_tmp.append(test_module.dict_values[i])
        interface_text = "%s(%s)\n" % (interface, ", ".join(param_tmp))

    return interface_text


def generate_compile_te(interface, idict, name="compiletest"):
    from .templates import test_module
    te = ""
    te += re.sub("TEMPLATETYPE", name, test_module.te_test_module)
    te += get_interface_compile_format_text(idict, interface)

    return te


def get_xml_file(if_file):
    """ Returns xml format of interfaces for given .if policy file"""
    import os
    try:
        from commands import getstatusoutput
    except ImportError:
        from subprocess import getstatusoutput
    basedir = os.path.dirname(if_file) + "/"
    filename = os.path.basename(if_file).split(".")[0]
    rc, output = getstatusoutput("/usr/bin/python3 /usr/share/selinux/devel/include/support/segenxml.py -w -m %s" % (basedir + filename))
    if rc != 0:
        sys.stderr.write("\n Could not process selected interface file.\n")
        sys.stderr.write("\n%s" % output)
        sys.exit(1)
    else:
        return output


def interface_compile_test(interface, path="/usr/share/selinux/devel/policy.xml"):
    exclude_interfaces = ["userdom", "kernel", "corenet", "files", "dev"]
    exclude_interface_type = ["template"]

    try:
        from commands import getstatusoutput
    except ImportError:
        from subprocess import getstatusoutput
    import os
    policy_files = {'pp': "compiletest.pp", 'te': "compiletest.te", 'fc': "compiletest.fc", 'if': "compiletest.if"}
    idict = get_interface_dict(path)

    if not (interface.split("_")[0] in exclude_interfaces or idict[interface][2] in exclude_interface_type):
        print(_("Compiling %s interface") % interface)
        try:
            fd = open(policy_files['te'], "w")
            fd.write(generate_compile_te(interface, idict))
            fd.close()
            rc, output = getstatusoutput("make -f /usr/share/selinux/devel/Makefile %s" % policy_files['pp'])
            if rc != 0:
                sys.stderr.write(output)
                sys.stderr.write(_("\nCompile test for %s failed.\n") % interface)

        except EnvironmentError as e:
            sys.stderr.write(_("\nCompile test for %s has not run. %s\n") % (interface, e))
        for v in policy_files.values():
            if os.path.exists(v):
                os.remove(v)

    else:
        sys.stderr.write(_("\nCompiling of %s interface is not supported.") % interface)
