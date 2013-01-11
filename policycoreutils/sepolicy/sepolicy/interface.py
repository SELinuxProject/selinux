#!/usr/bin/python -Es
#
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

import sepolgen.interfaces as interfaces
import sepolgen.defaults as defaults
ADMIN_TRANSITION_INTERFACE = "_admin$"
USER_TRANSITION_INTERFACE = "_role$"
from sepolicy.generate import get_all_types

__all__ = [ 'get', 'get_admin', 'get_user' ]

##
## I18N
##
PROGNAME="policycoreutils"

import gettext
gettext.bindtextdomain(PROGNAME, "/usr/share/locale")
gettext.textdomain(PROGNAME)
try:
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    unicode=False,
                    codeset = 'utf-8')
except IOError:
    import __builtin__
    __builtin__.__dict__['_'] = unicode

def get():
    """ Get all Methods """
    fn = defaults.interface_info()
    try:
        fd = open(fn)
        ifs = interfaces.InterfaceSet()
        ifs.from_file(fd)
        methods = ifs.interfaces.keys()
        fd.close()
    except:
        raise ValueError(_("could not open interface info [%s]\n") % fn)

    return methods

def get_admin():
    """ Get all domains with an admin interface"""
    admin_list = []
    for i in get():
        if i.endswith("_admin"):
            admin_list.append(i.split("_admin")[0])
    return admin_list

def get_user():
    """ Get all domains with SELinux user role interface"""
    trans_list = []
    for i in get():
        m = re.findall("(.*)%s" % USER_TRANSITION_INTERFACE, i)
        if len(m) > 0:
            if "%s_exec_t" % m[0] in get_all_types():
                trans_list.append(m[0])
    return trans_list
