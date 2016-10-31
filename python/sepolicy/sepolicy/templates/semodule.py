# Copyright (C) 2007-2012 Red Hat
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

########################### tmp Template File #############################
compile="""
#!/bin/sh
make -f /usr/share/selinux/devel/Makefile
semodule -i TEMPLATETYPE.pp
"""

restorecon="""
restorecon -R -v FILENAME
"""

tcp_ports="""
semanage ports -a -t TEMPLATETYPE_port_t -p tcp PORTNUM
"""

udp_ports="""
semanage ports -a -t TEMPLATETYPE_port_t -p udp PORTNUM
"""
