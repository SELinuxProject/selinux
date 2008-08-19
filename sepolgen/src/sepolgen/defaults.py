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
Various default settings, including file and directory locations.
"""

def data_dir():
    return "/var/lib/sepolgen"

def perm_map():
    return data_dir() + "/perm_map"

def interface_info():
    return data_dir() + "/interface_info"

def refpolicy_devel():
    return "/usr/share/selinux/devel"

def refpolicy_makefile():
    return refpolicy_devel() + "/Makefile"

def headers():
    return refpolicy_devel() + "/include"
    
