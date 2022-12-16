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
compile="""\
#!/bin/sh -e

DIRNAME=`dirname $0`
cd $DIRNAME
USAGE="$0 [ --update ]"
if [ `id -u` != 0 ]; then
echo 'You must be root to run this script'
exit 1
fi

if [ $# -eq 1 ]; then
	if [ "$1" = "--update" ] ; then
		time=`ls -l --time-style="+%x %X" TEMPLATEFILE.te | awk '{ printf "%s %s", $6, $7 }'`
		rules=`ausearch --start $time -m avc --raw -se TEMPLATETYPE`
		if [ x"$rules" != "x" ] ; then
			echo "Found avc's to update policy with"
			echo -e "$rules" | audit2allow -R
			echo "Do you want these changes added to policy [y/n]?"
			read ANS
			if [ "$ANS" = "y" -o "$ANS" = "Y" ] ; then
				echo "Updating policy"
				echo -e "$rules" | audit2allow -R >> TEMPLATEFILE.te
				# Fall though and rebuild policy
			else
				exit 0
			fi
		else
			echo "No new avcs found"
			exit 0
		fi
	else
		echo -e $USAGE
		exit 1
	fi
elif [ $# -ge 2 ] ; then
	echo -e $USAGE
	exit 1
fi

echo "Building and Loading Policy"
set -x
make -f /usr/share/selinux/devel/Makefile TEMPLATEFILE.pp || exit
/usr/sbin/semodule -i TEMPLATEFILE.pp

"""
rpm="""\
# Generate a rpm package for the newly generated policy

pwd=$(pwd)
rpmbuild --define "_sourcedir ${pwd}" --define "_specdir ${pwd}" --define "_builddir ${pwd}" --define "_srcrpmdir ${pwd}" --define "_rpmdir ${pwd}" --define "_buildrootdir ${pwd}/.build"  -ba TEMPLATEFILE_selinux.spec
"""

manpage="""\
# Generate a man page of the installed module
sepolicy manpage -p . -d DOMAINTYPE_t
"""

restorecon="""\
# Fixing the file context on FILENAME
/sbin/restorecon -F -R -v FILENAME
"""

tcp_ports="""\
# Adding SELinux tcp port to port PORTNUM
/usr/sbin/semanage port -a -t TEMPLATETYPE_port_t -p tcp PORTNUM
"""

udp_ports="""\
# Adding SELinux udp port to port PORTNUM
/usr/sbin/semanage port -a -t TEMPLATETYPE_port_t -p udp PORTNUM
"""

users="""\
# Adding SELinux user TEMPLATETYPE_u
/usr/sbin/semanage user -a -R "TEMPLATETYPE_rROLES" TEMPLATETYPE_u
"""

eusers="""\
# Adding roles to SELinux user TEMPLATETYPE_u
/usr/sbin/semanage user -m -R "TEMPLATETYPE_rROLES" TEMPLATETYPE_u
"""

admin_trans="""\
# Adding roles to SELinux user USER
/usr/sbin/semanage user -m -R +TEMPLATETYPE_r USER
"""

min_login_user_default_context="""\
cat > TEMPLATETYPE_u << _EOF
TEMPLATETYPE_r:TEMPLATETYPE_t:s0	TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:crond_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:initrc_su_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:local_login_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:remote_login_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:sshd_t			TEMPLATETYPE_r:TEMPLATETYPE_t
_EOF
if [ ! -f /etc/selinux/targeted/contexts/users/TEMPLATETYPE_u ]; then
   cp TEMPLATETYPE_u /etc/selinux/targeted/contexts/users/
fi
"""

x_login_user_default_context="""\
cat > TEMPLATETYPE_u << _EOF
TEMPLATETYPE_r:TEMPLATETYPE_t	TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:crond_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:initrc_su_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:local_login_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:remote_login_t		TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:sshd_t				TEMPLATETYPE_r:TEMPLATETYPE_t
system_r:xdm_t				TEMPLATETYPE_r:TEMPLATETYPE_t
_EOF
if [ ! -f /etc/selinux/targeted/contexts/users/TEMPLATETYPE_u ]; then
   cp TEMPLATETYPE_u /etc/selinux/targeted/contexts/users/
fi
"""
