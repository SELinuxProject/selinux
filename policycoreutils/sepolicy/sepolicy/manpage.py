#! /usr/bin/python -Es
# Copyright (C) 2012-2013 Red Hat
# AUTHOR: Dan Walsh <dwalsh@redhat.com>
# AUTHOR: Miroslav Grepl <mgrepl@redhat.com>
# see file 'COPYING' for use and warranty information
#
# semanage is a tool for managing SELinux configuration files
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
__all__ = ['ManPage', 'HTMLManPages', 'manpage_domains', 'manpage_roles', 'gen_domains']

import string
import selinux
import sepolicy
import os
import time

equiv_dict = {"smbd": ["samba"], "httpd": ["apache"], "virtd": ["virt", "libvirt", "svirt", "svirt_tcg", "svirt_lxc_t", "svirt_lxc_net_t"], "named": ["bind"], "fsdaemon": ["smartmon"], "mdadm": ["raid"]}

equiv_dirs = ["/var"]
modules_dict = None


def gen_modules_dict(path="/usr/share/selinux/devel/policy.xml"):
    global modules_dict
    if modules_dict:
        return modules_dict

    import xml.etree.ElementTree
    modules_dict = {}
    try:
        tree = xml.etree.ElementTree.fromstring(sepolicy.policy_xml(path))
        for l in tree.findall("layer"):
            for m in l.findall("module"):
                name = m.get("name")
                if name == "user" or name == "unconfined":
                    continue
                if name == "unprivuser":
                    name = "user"
                if name == "unconfineduser":
                    name = "unconfined"
                for b in m.findall("summary"):
                    modules_dict[name] = b.text
    except IOError:
        pass
    return modules_dict

users = None
users_range = None


def get_all_users_info():
    global users
    global users_range
    if users and users_range:
        return users, users_range

    users = []
    users_range = {}
    allusers = []
    allusers_info = sepolicy.info(sepolicy.USER)

    for d in allusers_info:
        allusers.append(d['name'])
        users_range[d['name'].split("_")[0]] = d['range']

    for u in allusers:
        if u not in ["system_u", "root", "unconfined_u"]:
            users.append(u.replace("_u", ""))
    users.sort()
    return users, users_range

all_entrypoints = None


def get_entrypoints():
    global all_entrypoints
    if not all_entrypoints:
        all_entrypoints = sepolicy.info(sepolicy.ATTRIBUTE, "entry_type")[0]["types"]
    return all_entrypoints

domains = None


def gen_domains():
    global domains
    if domains:
        return domains
    domains = []
    for d in sepolicy.get_all_domains():
        found = False
        domain = d[:-2]
#		if domain + "_exec_t" not in get_entrypoints():
#			continue
        if domain in domains:
            continue
        domains.append(domain)

    for role in sepolicy.get_all_roles():
        if role[:-2] in domains or role == "system_r":
            continue
        domains.append(role[:-2])

    domains.sort()
    return domains

types = None


def _gen_types():
    global types
    if types:
        return types
    all_types = sepolicy.info(sepolicy.TYPE)
    types = {}
    for rec in all_types:
        try:
            types[rec["name"]] = rec["attributes"]
        except:
            types[rec["name"]] = []
    return types


def prettyprint(f, trim):
    return " ".join(f[:-len(trim)].split("_"))

# for HTML man pages
manpage_domains = []
manpage_roles = []

fedora_releases = ["Fedora17", "Fedora18"]
rhel_releases = ["RHEL6", "RHEL7"]


def get_alphabet_manpages(manpage_list):
    alphabet_manpages = dict.fromkeys(string.ascii_letters, [])
    for i in string.ascii_letters:
        temp = []
        for j in manpage_list:
            if j.split("/")[-1][0] == i:
                temp.append(j.split("/")[-1])

        alphabet_manpages[i] = temp

    return alphabet_manpages


def convert_manpage_to_html(html_manpage, manpage):
    try:
            from commands import getstatusoutput
    except ImportError:
            from subprocess import getstatusoutput
    rc, output = getstatusoutput("/usr/bin/groff -man -Thtml %s 2>/dev/null" % manpage)
    if rc == 0:
        print(html_manpage, "has been created")
        fd = open(html_manpage, 'w')
        fd.write(output)
        fd.close()


class HTMLManPages:

    """
            Generate a HHTML Manpages on an given SELinux domains
    """

    def __init__(self, manpage_roles, manpage_domains, path, os_version):
        self.manpage_roles = get_alphabet_manpages(manpage_roles)
        self.manpage_domains = get_alphabet_manpages(manpage_domains)
        self.os_version = os_version
        self.old_path = path + "/"
        self.new_path = self.old_path + self.os_version + "/"

        if self.os_version in fedora_releases or rhel_releases:
            self.__gen_html_manpages()
        else:
            print("SELinux HTML man pages can not be generated for this %s" % os_version)
            exit(1)

    def __gen_html_manpages(self):
        self._write_html_manpage()
        self._gen_index()
        self._gen_body()
        self._gen_css()

    def _write_html_manpage(self):
        if not os.path.isdir(self.new_path):
            os.mkdir(self.new_path)

        for domain in self.manpage_domains.values():
            if len(domain):
                for d in domain:
                    convert_manpage_to_html((self.new_path + d.split("_selinux")[0] + ".html"), self.old_path + d)

        for role in self.manpage_roles.values():
            if len(role):
                for r in role:
                    convert_manpage_to_html((self.new_path + r.split("_selinux")[0] + ".html"), self.old_path + r)

    def _gen_index(self):
        index = self.old_path + "index.html"
        fd = open(index, 'w')
        fd.write("""
<html>
<head>
    <link rel=stylesheet type="text/css" href="style.css" title="style">
    <title>SELinux man pages online</title>
</head>
<body>
<h1>SELinux man pages</h1>
<br></br>
Fedora or Red Hat Enterprise Linux Man Pages.</h2>
<br></br>
<hr>
<h3>Fedora</h3>
<table><tr>
<td valign="middle">
</td>
</tr></table>
<pre>
""")
        for f in fedora_releases:
            fd.write("""
<a href=%s/%s.html>%s</a> - SELinux man pages for %s """ % (f, f, f, f))

        fd.write("""
</pre>
<hr>
<h3>RHEL</h3>
<table><tr>
<td valign="middle">
</td>
</tr></table>
<pre>
""")
        for r in rhel_releases:
            fd.write("""
<a href=%s/%s.html>%s</a> - SELinux man pages for %s """ % (r, r, r, r))

        fd.write("""
</pre>
	""")
        fd.close()
        print("%s has been created") % index

    def _gen_body(self):
        html = self.new_path + self.os_version + ".html"
        fd = open(html, 'w')
        fd.write("""
<html>
<head>
	<link rel=stylesheet type="text/css" href="../style.css" title="style">
	<title>Linux man-pages online for Fedora18</title>
</head>
<body>
<h1>SELinux man pages for Fedora18</h1>
<hr>
<table><tr>
<td valign="middle">
<h3>SELinux roles</h3>
""")
        for letter in self.manpage_roles:
            if len(self.manpage_roles[letter]):
                fd.write("""
<a href=#%s_role>%s</a>"""
                         % (letter, letter))

        fd.write("""
</td>
</tr></table>
<pre>
""")
        rolename_body = ""
        for letter in self.manpage_roles:
            if len(self.manpage_roles[letter]):
                rolename_body += "<p>"
                for r in self.manpage_roles[letter]:
                    rolename = r.split("_selinux")[0]
                    rolename_body += "<a name=%s_role></a><a href=%s.html>%s_selinux(8)</a> - Security Enhanced Linux Policy for the %s SELinux user\n" % (letter, rolename, rolename, rolename)

        fd.write("""%s
</pre>
<hr>
<table><tr>
<td valign="middle">
<h3>SELinux domains</h3>"""
                 % rolename_body)

        for letter in self.manpage_domains:
            if len(self.manpage_domains[letter]):
                fd.write("""
<a href=#%s_domain>%s</a>
			""" % (letter, letter))

        fd.write("""
</td>
</tr></table>
<pre>
""")
        domainname_body = ""
        for letter in self.manpage_domains:
            if len(self.manpage_domains[letter]):
                domainname_body += "<p>"
                for r in self.manpage_domains[letter]:
                    domainname = r.split("_selinux")[0]
                    domainname_body += "<a name=%s_domain></a><a href=%s.html>%s_selinux(8)</a> - Security Enhanced Linux Policy for the %s SELinux processes\n" % (letter, domainname, domainname, domainname)

        fd.write("""%s
</pre>
</body>
</html>
""" % domainname_body)

        fd.close()
        print("%s has been created") % html

    def _gen_css(self):
        style_css = self.old_path + "style.css"
        fd = open(style_css, 'w')
        fd.write("""
html, body {
    background-color: #fcfcfc;
    font-family: arial, sans-serif;
    font-size: 110%;
    color: #333;
}

h1, h2, h3, h4, h5, h5 {
	color: #2d7c0b;
	font-family: arial, sans-serif;
	margin-top: 25px;
}

a {
    color: #336699;
    text-decoration: none;
}

a:visited {
    color: #4488bb;
}

a:hover, a:focus, a:active {
    color: #07488A;
    text-decoration: none;
}

a.func {
    color: red;
    text-decoration: none;
}
a.file {
    color: red;
    text-decoration: none;
}

pre.code {
    background-color: #f4f0f4;
//    font-family: monospace, courier;
    font-size: 110%;
    margin-left: 0px;
    margin-right: 60px;
    padding-top: 5px;
    padding-bottom: 5px;
    padding-left: 8px;
    padding-right: 8px;
    border: 1px solid #AADDAA;
}

.url {
    font-family: serif;
    font-style: italic;
    color: #440064;
}
""")

        fd.close()
        print("%s has been created") % style_css


class ManPage:

    """
        Generate a Manpage on an SELinux domain in the specified path
    """
    modules_dict = None
    enabled_str = ["Disabled", "Enabled"]

    def __init__(self, domainname, path="/tmp", root="/", source_files=False, html=False):
        self.html = html
        self.source_files = source_files
        self.root = root
        self.portrecs = sepolicy.gen_port_dict()[0]
        self.domains = gen_domains()
        self.all_domains = sepolicy.get_all_domains()
        self.all_attributes = sepolicy.get_all_attributes()
        self.all_bools = sepolicy.get_all_bools()
        self.all_port_types = sepolicy.get_all_port_types()
        self.all_roles = sepolicy.get_all_roles()
        self.all_users = get_all_users_info()[0]
        self.all_users_range = get_all_users_info()[1]
        self.all_file_types = sepolicy.get_all_file_types()
        self.role_allows = sepolicy.get_all_role_allows()
        self.types = _gen_types()

        if self.source_files:
            self.fcpath = self.root + "file_contexts"
        else:
            self.fcpath = self.root + selinux.selinux_file_context_path()

        self.fcdict = sepolicy.get_fcdict(self.fcpath)

        if not os.path.exists(path):
            os.makedirs(path)

        self.path = path

        if self.source_files:
            self.xmlpath = self.root + "policy.xml"
        else:
            self.xmlpath = self.root + "/usr/share/selinux/devel/policy.xml"
        self.booleans_dict = sepolicy.gen_bool_dict(self.xmlpath)

        self.domainname, self.short_name = sepolicy.gen_short_name(domainname)

        self.type = self.domainname + "_t"
        self._gen_bools()
        self.man_page_path = "%s/%s_selinux.8" % (path, self.domainname)
        self.fd = open(self.man_page_path, 'w')
        if self.domainname + "_r" in self.all_roles:
            self.__gen_user_man_page()
            if self.html:
                manpage_roles.append(self.man_page_path)
        else:
            if self.html:
                manpage_domains.append(self.man_page_path)
            self.__gen_man_page()
        self.fd.close()

        for k in equiv_dict.keys():
            if k == self.domainname:
                for alias in equiv_dict[k]:
                    self.__gen_man_page_link(alias)

    def _gen_bools(self):
        self.bools = []
        self.domainbools = []
        types = [self.type]
        if self.domainname in equiv_dict:
            for t in equiv_dict[self.domainname]:
                if t + "_t" in self.all_domains:
                    types.append(t + "_t")

        for t in types:
            domainbools, bools = sepolicy.get_bools(t)
            self.bools += bools
            self.domainbools += domainbools

        self.bools.sort()
        self.domainbools.sort()

    def get_man_page_path(self):
        return self.man_page_path

    def __gen_user_man_page(self):
        self.role = self.domainname + "_r"
        if not self.modules_dict:
            self.modules_dict = gen_modules_dict(self.xmlpath)

        try:
            self.desc = self.modules_dict[self.domainname]
        except:
            self.desc = "%s user role" % self.domainname

        if self.domainname in self.all_users:
            self.attributes = sepolicy.info(sepolicy.TYPE, (self.type))[0]["attributes"]
            self._user_header()
            self._user_attribute()
            self._can_sudo()
            self._xwindows_login()
            # until a new policy build with login_userdomain attribute
        #self.terminal_login()
            self._network()
            self._booleans()
            self._home_exec()
            self._transitions()
        else:
            self._role_header()
            self._booleans()

        self._port_types()
        self._writes()
        self._footer()

    def __gen_man_page_link(self, alias):
        path = "%s/%s_selinux.8" % (self.path, alias)
        self.fd = open("%s/%s_selinux.8" % (self.path, alias), 'w')
        self.fd.write(".so man8/%s_selinux.8" % self.domainname)
        self.fd.close()
        print(path)

    def __gen_man_page(self):
        self.anon_list = []

        self.attributes = {}
        self.ptypes = []
        self._get_ptypes()

        for domain_type in self.ptypes:
            self.attributes[domain_type] = sepolicy.info(sepolicy.TYPE, ("%s") % domain_type)[0]["attributes"]

        self._header()
        self._entrypoints()
        self._process_types()
        self._booleans()
        self._nsswitch_domain()
        self._port_types()
        self._writes()
        self._file_context()
        self._public_content()
        self._footer()

    def _get_ptypes(self):
        for f in self.all_domains:
            if f.startswith(self.short_name) or f.startswith(self.domainname):
                self.ptypes.append(f)

    def _header(self):
        self.fd.write('.TH  "%(domainname)s_selinux"  "8"  "%(date)s" "%(domainname)s" "SELinux Policy %(domainname)s"'
                      % {'domainname': self.domainname, 'date': time.strftime("%y-%m-%d")})
        self.fd.write(r"""
.SH "NAME"
%(domainname)s_selinux \- Security Enhanced Linux Policy for the %(domainname)s processes
.SH "DESCRIPTION"

Security-Enhanced Linux secures the %(domainname)s processes via flexible mandatory access control.

The %(domainname)s processes execute with the %(domainname)s_t SELinux type. You can check if you have these processes running by executing the \fBps\fP command with the \fB\-Z\fP qualifier.

For example:

.B ps -eZ | grep %(domainname)s_t

""" % {'domainname': self.domainname})

    def _format_boolean_desc(self, b):
        desc = self.booleans_dict[b][2][0].lower() + self.booleans_dict[b][2][1:]
        if desc[-1] == ".":
            desc = desc[:-1]
        return desc

    def _gen_bool_text(self):
        booltext = ""
        for b, enabled in self.domainbools + self.bools:
            if b.endswith("anon_write") and b not in self.anon_list:
                self.anon_list.append(b)
            else:
                if b not in self.booleans_dict:
                    continue
                booltext += """
.PP
If you want to %s, you must turn on the %s boolean. %s by default.

.EX
.B setsebool -P %s 1

.EE
""" % (self._format_boolean_desc(b), b, self.enabled_str[enabled], b)
        return booltext

    def _booleans(self):
        self.booltext = self._gen_bool_text()

        if self.booltext != "":
            self.fd.write("""
.SH BOOLEANS
SELinux policy is customizable based on least access required.  %s policy is extremely flexible and has several booleans that allow you to manipulate the policy and run %s with the tightest access possible.

""" % (self.domainname, self.domainname))

            self.fd.write(self.booltext)

    def _nsswitch_domain(self):
        nsswitch_types = []
        nsswitch_booleans = ['authlogin_nsswitch_use_ldap', 'kerberos_enabled']
        nsswitchbooltext = ""
        for k in self.attributes.keys():
            if "nsswitch_domain" in self.attributes[k]:
                nsswitch_types.append(k)

        if len(nsswitch_types):
            self.fd.write("""
.SH NSSWITCH DOMAIN
""")
            for b in nsswitch_booleans:
                nsswitchbooltext += """
.PP
If you want to %s for the %s, you must turn on the %s boolean.

.EX
.B setsebool -P %s 1
.EE
""" % (self._format_boolean_desc(b), (", ".join(nsswitch_types)), b, b)

        self.fd.write(nsswitchbooltext)

    def _process_types(self):
        if len(self.ptypes) == 0:
            return
        self.fd.write(r"""
.SH PROCESS TYPES
SELinux defines process types (domains) for each process running on the system
.PP
You can see the context of a process using the \fB\-Z\fP option to \fBps\bP
.PP
Policy governs the access confined processes have to files.
SELinux %(domainname)s policy is very flexible allowing users to setup their %(domainname)s processes in as secure a method as possible.
.PP
The following process types are defined for %(domainname)s:
""" % {'domainname': self.domainname})
        self.fd.write("""
.EX
.B %s
.EE""" % ", ".join(self.ptypes))
        self.fd.write("""
.PP
Note:
.B semanage permissive -a %(domainname)s_t
can be used to make the process type %(domainname)s_t permissive. SELinux does not deny access to permissive process types, but the AVC (SELinux denials) messages are still generated.
""" % {'domainname': self.domainname})

    def _port_types(self):
        self.ports = []
        for f in self.all_port_types:
            if f.startswith(self.short_name) or f.startswith(self.domainname):
                self.ports.append(f)

        if len(self.ports) == 0:
            return
        self.fd.write("""
.SH PORT TYPES
SELinux defines port types to represent TCP and UDP ports.
.PP
You can see the types associated with a port by using the following command:

.B semanage port -l

.PP
Policy governs the access confined processes have to these ports.
SELinux %(domainname)s policy is very flexible allowing users to setup their %(domainname)s processes in as secure a method as possible.
.PP
The following port types are defined for %(domainname)s:""" % {'domainname': self.domainname})

        for p in self.ports:
            self.fd.write("""

.EX
.TP 5
.B %s
.TP 10
.EE
""" % p)
            once = True
            for prot in ("tcp", "udp"):
                if (p, prot) in self.portrecs:
                    if once:
                        self.fd.write("""

Default Defined Ports:""")
                    once = False
                    self.fd.write(r"""
%s %s
.EE""" % (prot, ",".join(self.portrecs[(p, prot)])))

    def _file_context(self):
        flist = []
        mpaths = []
        for f in self.all_file_types:
            if f.startswith(self.domainname):
                flist.append(f)
                if f in self.fcdict:
                    mpaths = mpaths + self.fcdict[f]["regex"]
        if len(mpaths) == 0:
            return
        mpaths.sort()
        mdirs = {}
        for mp in mpaths:
            found = False
            for md in mdirs:
                if mp.startswith(md):
                    mdirs[md].append(mp)
                    found = True
                    break
            if not found:
                for e in equiv_dirs:
                    if mp.startswith(e) and mp.endswith('(/.*)?'):
                        mdirs[mp[:-6]] = []
                        break

        equiv = []
        for m in mdirs:
            if len(mdirs[m]) > 0:
                equiv.append(m)

        self.fd.write(r"""
.SH FILE CONTEXTS
SELinux requires files to have an extended attribute to define the file type.
.PP
You can see the context of a file using the \fB\-Z\fP option to \fBls\bP
.PP
Policy governs the access confined processes have to these files.
SELinux %(domainname)s policy is very flexible allowing users to setup their %(domainname)s processes in as secure a method as possible.
.PP
""" % {'domainname': self.domainname})

        if len(equiv) > 0:
            self.fd.write(r"""
.PP
.B EQUIVALENCE DIRECTORIES
""")
            for e in equiv:
                self.fd.write(r"""
.PP
%(domainname)s policy stores data with multiple different file context types under the %(equiv)s directory.  If you would like to store the data in a different directory you can use the semanage command to create an equivalence mapping.  If you wanted to store this data under the /srv dirctory you would execute the following command:
.PP
.B semanage fcontext -a -e %(equiv)s /srv/%(alt)s
.br
.B restorecon -R -v /srv/%(alt)s
.PP
""" % {'domainname': self.domainname, 'equiv': e, 'alt': e.split('/')[-1]})

        self.fd.write(r"""
.PP
.B STANDARD FILE CONTEXT

SELinux defines the file context types for the %(domainname)s, if you wanted to
store files with these types in a diffent paths, you need to execute the semanage command to sepecify alternate labeling and then use restorecon to put the labels on disk.

.B semanage fcontext -a -t %(type)s '/srv/%(domainname)s/content(/.*)?'
.br
.B restorecon -R -v /srv/my%(domainname)s_content

Note: SELinux often uses regular expressions to specify labels that match multiple files.
""" % {'domainname': self.domainname, "type": flist[0]})

        self.fd.write(r"""
.I The following file types are defined for %(domainname)s:
""" % {'domainname': self.domainname})
        for f in flist:
            self.fd.write("""

.EX
.PP
.B %s
.EE

- %s
""" % (f, sepolicy.get_description(f)))

            if f in self.fcdict:
                plural = ""
                if len(self.fcdict[f]["regex"]) > 1:
                    plural = "s"
                    self.fd.write("""
.br
.TP 5
Path%s:
%s""" % (plural, self.fcdict[f]["regex"][0]))
                    for x in self.fcdict[f]["regex"][1:]:
                        self.fd.write(", %s" % x)

        self.fd.write("""

.PP
Note: File context can be temporarily modified with the chcon command.  If you want to permanently change the file context you need to use the
.B semanage fcontext
command.  This will modify the SELinux labeling database.  You will need to use
.B restorecon
to apply the labels.
""")

    def _see_also(self):
        ret = ""
        for d in self.domains:
            if d == self.domainname:
                continue
            if d.startswith(self.short_name):
                ret += ", %s_selinux(8)" % d
            if d.startswith(self.domainname + "_"):
                ret += ", %s_selinux(8)" % d
        self.fd.write(ret)

    def _public_content(self):
        if len(self.anon_list) > 0:
            self.fd.write("""
.SH SHARING FILES
If you want to share files with multiple domains (Apache, FTP, rsync, Samba), you can set a file context of public_content_t and public_content_rw_t.  These context allow any of the above domains to read the content.  If you want a particular domain to write to the public_content_rw_t domain, you must set the appropriate boolean.
.TP
Allow %(domainname)s servers to read the /var/%(domainname)s directory by adding the public_content_t file type to the directory and by restoring the file type.
.PP
.B
semanage fcontext -a -t public_content_t "/var/%(domainname)s(/.*)?"
.br
.B restorecon -F -R -v /var/%(domainname)s
.pp
.TP
Allow %(domainname)s servers to read and write /var/%(domainname)s/incoming by adding the public_content_rw_t type to the directory and by restoring the file type.  You also need to turn on the %(domainname)s_anon_write boolean.
.PP
.B
semanage fcontext -a -t public_content_rw_t "/var/%(domainname)s/incoming(/.*)?"
.br
.B restorecon -F -R -v /var/%(domainname)s/incoming
.br
.B setsebool -P %(domainname)s_anon_write 1
""" % {'domainname': self.domainname})
            for b in self.anon_list:
                desc = self.booleans_dict[b][2][0].lower() + self.booleans_dict[b][2][1:]
                self.fd.write("""
.PP
If you want to %s, you must turn on the %s boolean.

.EX
.B setsebool -P %s 1
.EE
""" % (desc, b, b))

    def _footer(self):
        self.fd.write("""
.SH "COMMANDS"
.B semanage fcontext
can also be used to manipulate default file context mappings.
.PP
.B semanage permissive
can also be used to manipulate whether or not a process type is permissive.
.PP
.B semanage module
can also be used to enable/disable/install/remove policy modules.
""")

        if len(self.ports) > 0:
            self.fd.write("""
.B semanage port
can also be used to manipulate the port definitions
""")

        if self.booltext != "":
            self.fd.write("""
.B semanage boolean
can also be used to manipulate the booleans
""")

        self.fd.write("""
.PP
.B system-config-selinux
is a GUI tool available to customize SELinux policy settings.

.SH AUTHOR
This manual page was auto-generated using
.B "sepolicy manpage".

.SH "SEE ALSO"
selinux(8), %s(8), semanage(8), restorecon(8), chcon(1), sepolicy(8)
""" % (self.domainname))

        if self.booltext != "":
            self.fd.write(", setsebool(8)")

        self._see_also()

    def _valid_write(self, check, attributes):
        if check in [self.type, "domain"]:
            return False
        if check.endswith("_t"):
            for a in attributes:
                if a in self.types[check]:
                    return False
        return True

    def _entrypoints(self):
        try:
            entrypoints = map(lambda x: x['target'], sepolicy.search([sepolicy.ALLOW], {'source': self.type, 'permlist': ['entrypoint'], 'class': 'file'}))
        except:
            return

        self.fd.write("""
.SH "ENTRYPOINTS"
""")
        if len(entrypoints) > 1:
            entrypoints_str = "\\fB%s\\fP file types" % ", ".join(entrypoints)
        else:
            entrypoints_str = "\\fB%s\\fP file type" % entrypoints[0]

        self.fd.write("""
The %s_t SELinux type can be entered via the %s.

The default entrypoint paths for the %s_t domain are the following:
""" % (self.domainname, entrypoints_str, self.domainname))
        if "bin_t" in entrypoints:
            entrypoints.remove("bin_t")
            self.fd.write("""
All executeables with the default executable label, usually stored in /usr/bin and /usr/sbin.""")

        paths = []
        for entrypoint in entrypoints:
            if entrypoint in self.fcdict:
                paths += self.fcdict[entrypoint]["regex"]

        self.fd.write("""
%s""" % ", ".join(paths))

    def _writes(self):
        permlist = sepolicy.search([sepolicy.ALLOW], {'source': self.type, 'permlist': ['open', 'write'], 'class': 'file'})
        if permlist is None or len(permlist) == 0:
            return

        all_writes = []
        attributes = ["proc_type", "sysctl_type"]
        for i in permlist:
            if not i['target'].endswith("_t"):
                attributes.append(i['target'])

        for i in permlist:
            if self._valid_write(i['target'], attributes):
                if i['target'] not in all_writes:
                    all_writes.append(i['target'])

        if len(all_writes) == 0:
            return
        self.fd.write("""
.SH "MANAGED FILES"
""")
        self.fd.write("""
The SELinux process type %s_t can manage files labeled with the following file types.  The paths listed are the default paths for these file types.  Note the processes UID still need to have DAC permissions.
""" % self.domainname)

        all_writes.sort()
        if "file_type" in all_writes:
            all_writes = ["file_type"]
        for f in all_writes:
            self.fd.write("""
.br
.B %s

""" % f)
            if f in self.fcdict:
                for path in self.fcdict[f]["regex"]:
                    self.fd.write("""\t%s
.br
""" % path)

    def _get_users_range(self):
        if self.domainname in self.all_users_range:
            return self.all_users_range[self.domainname]
        return "s0"

    def _user_header(self):
        self.fd.write('.TH  "%(type)s_selinux"  "8"  "%(type)s" "mgrepl@redhat.com" "%(type)s SELinux Policy documentation"'
                      % {'type': self.domainname})

        self.fd.write(r"""
.SH "NAME"
%(user)s_u \- \fB%(desc)s\fP - Security Enhanced Linux Policy

.SH DESCRIPTION

\fB%(user)s_u\fP is an SELinux User defined in the SELinux
policy. SELinux users have default roles, \fB%(user)s_r\fP.  The
default role has a default type, \fB%(user)s_t\fP, associated with it.

The SELinux user will usually login to a system with a context that looks like:

.B %(user)s_u:%(user)s_r:%(user)s_t:%(range)s

Linux users are automatically assigned an SELinux users at login.
Login programs use the SELinux User to assign initial context to the user's shell.

SELinux policy uses the context to control the user's access.

By default all users are assigned to the SELinux user via the \fB__default__\fP flag

On Targeted policy systems the \fB__default__\fP user is assigned to the \fBunconfined_u\fP SELinux user.

You can list all Linux User to SELinux user mapping using:

.B semanage login -l

If you wanted to change the default user mapping to use the %(user)s_u user, you would execute:

.B semanage login -m -s %(user)s_u __default__

""" % {'desc': self.desc, 'type': self.type, 'user': self.domainname, 'range': self._get_users_range()})

        if "login_userdomain" in self.attributes and "login_userdomain" in self.all_attributes:
            self.fd.write("""
If you want to map the one Linux user (joe) to the SELinux user %(user)s, you would execute:

.B $ semanage login -a -s %(user)s_u joe

""" % {'user': self.domainname})

    def _can_sudo(self):
        sudotype = "%s_sudo_t" % self.domainname
        self.fd.write("""
.SH SUDO
""")
        if sudotype in self.types:
            role = self.domainname + "_r"
            self.fd.write("""
The SELinux user %(user)s can execute sudo.

You can set up sudo to allow %(user)s to transition to an administrative domain:

Add one or more of the following record to sudoers using visudo.

""" % {'user': self.domainname})
            for adminrole in self.role_allows[role]:
                self.fd.write("""
USERNAME ALL=(ALL) ROLE=%(admin)s_r TYPE=%(admin)s_t COMMAND
.br
sudo will run COMMAND as %(user)s_u:%(admin)s_r:%(admin)s_t:LEVEL
""" % {'admin': adminrole[:-2], 'user': self.domainname})

                self.fd.write("""
You might also need to add one or more of these new roles to your SELinux user record.

List the SELinux roles your SELinux user can reach by executing:

.B $ semanage user -l |grep selinux_name

Modify the roles list and add %(user)s_r to this list.

.B $ semanage user -m -R '%(roles)s' %(user)s_u

For more details you can see semanage man page.

""" % {'user': self.domainname, "roles": " ".join([role] + self.role_allows[role])})
            else:
                self.fd.write("""
The SELinux type %s_t is not allowed to execute sudo.
""" % self.domainname)

    def _user_attribute(self):
        self.fd.write("""
.SH USER DESCRIPTION
""")
        if "unconfined_usertype" in self.attributes:
            self.fd.write("""
The SELinux user %s_u is an unconfined user. It means that a mapped Linux user to this SELinux user is supposed to be allow all actions.
""" % self.domainname)

        if "unpriv_userdomain" in self.attributes:
            self.fd.write("""
The SELinux user %s_u is defined in policy as a unprivileged user. SELinux prevents unprivileged users from doing administration tasks without transitioning to a different role.
""" % self.domainname)

        if "admindomain" in self.attributes:
            self.fd.write("""
The SELinux user %s_u is an admin user. It means that a mapped Linux user to this SELinux user is intended for administrative actions. Usually this is assigned to a root Linux user.
""" % self.domainname)

    def _xwindows_login(self):
        if "x_domain" in self.all_attributes:
            self.fd.write("""
.SH X WINDOWS LOGIN
""")
            if "x_domain" in self.attributes:
                self.fd.write("""
The SELinux user %s_u is able to X Windows login.
""" % self.domainname)
            else:
                self.fd.write("""
The SELinux user %s_u is not able to X Windows login.
""" % self.domainname)

    def _terminal_login(self):
        if "login_userdomain" in self.all_attributes:
            self.fd.write("""
.SH TERMINAL LOGIN
""")
            if "login_userdomain" in self.attributes:
                self.fd.write("""
The SELinux user %s_u is able to terminal login.
""" % self.domainname)
            else:
                self.fd.write("""
The SELinux user %s_u is not able to terminal login.
""" % self.domainname)

    def _network(self):
        from sepolicy import network
        self.fd.write("""
.SH NETWORK
""")
        for net in ("tcp", "udp"):
            portdict = network.get_network_connect(self.type, net, "name_bind")
            if len(portdict) > 0:
                self.fd.write("""
.TP
The SELinux user %s_u is able to listen on the following %s ports.
""" % (self.domainname, net))
                for p in portdict:
                    for t, ports in portdict[p]:
                        self.fd.write("""
.B %s
""" % ",".join(ports))
            portdict = network.get_network_connect(self.type, "tcp", "name_connect")
            if len(portdict) > 0:
                self.fd.write("""
.TP
The SELinux user %s_u is able to connect to the following tcp ports.
""" % (self.domainname))
                for p in portdict:
                    for t, ports in portdict[p]:
                        self.fd.write("""
.B %s
""" % ",".join(ports))

    def _home_exec(self):
        permlist = sepolicy.search([sepolicy.ALLOW], {'source': self.type, 'target': 'user_home_type', 'class': 'file', 'permlist': ['ioctl', 'read', 'getattr', 'execute', 'execute_no_trans', 'open']})
        self.fd.write("""
.SH HOME_EXEC
""")
        if permlist is not None:
            self.fd.write("""
The SELinux user %s_u is able execute home content files.
""" % self.domainname)

        else:
            self.fd.write("""
The SELinux user %s_u is not able execute home content files.
""" % self.domainname)

    def _transitions(self):
        self.fd.write(r"""
.SH TRANSITIONS

Three things can happen when %(type)s attempts to execute a program.

\fB1.\fP SELinux Policy can deny %(type)s from executing the program.

.TP

\fB2.\fP SELinux Policy can allow %(type)s to execute the program in the current user type.

Execute the following to see the types that the SELinux user %(type)s can execute without transitioning:

.B search -A -s %(type)s -c file -p execute_no_trans

.TP

\fB3.\fP SELinux can allow %(type)s to execute the program and transition to a new type.

Execute the following to see the types that the SELinux user %(type)s can execute and transition:

.B $ search -A -s %(type)s -c process -p transition

""" % {'user': self.domainname, 'type': self.type})

    def _role_header(self):
        self.fd.write('.TH  "%(user)s_selinux"  "8"  "%(user)s" "mgrepl@redhat.com" "%(user)s SELinux Policy documentation"'
                      % {'user': self.domainname})

        self.fd.write(r"""
.SH "NAME"
%(user)s_r \- \fB%(desc)s\fP - Security Enhanced Linux Policy

.SH DESCRIPTION

SELinux supports Roles Based Access Control (RBAC), some Linux roles are login roles, while other roles need to be transition into.

.I Note:
Examples in this man page will use the
.B staff_u
SELinux user.

Non login roles are usually used for administrative tasks. For example, tasks that require root privileges.  Roles control which types a user can run processes with. Roles often have default types assigned to them.

The default type for the %(user)s_r role is %(user)s_t.

The
.B newrole
program to transition directly to this role.

.B newrole -r %(user)s_r -t %(user)s_t

.B sudo
is the preferred method to do transition from one role to another.  You setup sudo to transition to %(user)s_r by adding a similar line to the /etc/sudoers file.

USERNAME ALL=(ALL) ROLE=%(user)s_r TYPE=%(user)s_t COMMAND

.br
sudo will run COMMAND as staff_u:%(user)s_r:%(user)s_t:LEVEL

When using a a non login role, you need to setup SELinux so that your SELinux user can reach %(user)s_r role.

Execute the following to see all of the assigned SELinux roles:

.B semanage user -l

You need to add %(user)s_r to the staff_u user.  You could setup the staff_u user to be able to use the %(user)s_r role with a command like:

.B $ semanage user -m -R 'staff_r system_r %(user)s_r' staff_u

""" % {'desc': self.desc, 'user': self.domainname})
        troles = []
        for i in self.role_allows:
            if self.domainname + "_r" in self.role_allows[i]:
                troles.append(i)
        if len(troles) > 0:
            plural = ""
            if len(troles) > 1:
                plural = "s"

                self.fd.write("""

SELinux policy also controls which roles can transition to a different role.
You can list these rules using the following command.

.B search --role_allow

SELinux policy allows the %s role%s can transition to the %s_r role.

""" % (", ".join(troles), plural, self.domainname))
