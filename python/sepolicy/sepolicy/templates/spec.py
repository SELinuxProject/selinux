header_comment_section="""\
# vim: sw=4:ts=4:et
"""

base_section="""\

%define selinux_policyver VERSION

Name:   MODULENAME_selinux
Version:	1.0
Release:	1%{?dist}
Summary:	SELinux policy module for MODULENAME

Group:	System Environment/Base		
License:	GPLv2+	
# This is an example. You will need to change it.
URL:		http://HOSTNAME
Source0:	MODULENAME.pp
Source1:	MODULENAME.if
Source2:	DOMAINNAME_selinux.8
Source3:	DOMAINNAME_u

Requires: policycoreutils, libselinux-utils
Requires(post): selinux-policy-base >= %{selinux_policyver}, policycoreutils
Requires(postun): policycoreutils
"""

mid_section="""\
BuildArch: noarch

%description
This package installs and sets up the  SELinux policy security module for MODULENAME.

%install
install -d %{buildroot}%{_datadir}/selinux/packages
install -m 644 %{SOURCE0} %{buildroot}%{_datadir}/selinux/packages
install -d %{buildroot}%{_datadir}/selinux/devel/include/contrib
install -m 644 %{SOURCE1} %{buildroot}%{_datadir}/selinux/devel/include/contrib/
install -d %{buildroot}%{_mandir}/man8/
install -m 644 %{SOURCE2} %{buildroot}%{_mandir}/man8/DOMAINNAME_selinux.8
install -d %{buildroot}/etc/selinux/targeted/contexts/users/
install -m 644 %{SOURCE3} %{buildroot}/etc/selinux/targeted/contexts/users/DOMAINNAME_u

%post
semodule -n -i %{_datadir}/selinux/packages/MODULENAME.pp
# Add the new user defined in DOMAINNAME_u only when the package is installed (not during updates)
if [ $1 -eq 1 ]; then
    /usr/sbin/semanage user -a -R DOMAINNAME_r DOMAINNAME_u
fi
if /usr/sbin/selinuxenabled ; then
    /usr/sbin/load_policy
    %relabel_files
fi;
exit 0

%postun
if [ $1 -eq 0 ]; then
    /usr/sbin/semanage user -d DOMAINNAME_u
    semodule -n -r MODULENAME
    if /usr/sbin/selinuxenabled ; then
       /usr/sbin/load_policy
       %relabel_files
    fi;
fi;
exit 0

%files
%attr(0600,root,root) %{_datadir}/selinux/packages/MODULENAME.pp
%{_datadir}/selinux/devel/include/contrib/MODULENAME.if
%{_mandir}/man8/DOMAINNAME_selinux.8.*
/etc/selinux/targeted/contexts/users/DOMAINNAME_u

%changelog
* TODAYSDATE YOUR NAME <YOUR@EMAILADDRESS> 1.0-1
- Initial version

"""

define_relabel_files_begin ="""\
\n
%define relabel_files() \\
"""

define_relabel_files_end ="""\
restorecon -R FILENAME; \\
"""
