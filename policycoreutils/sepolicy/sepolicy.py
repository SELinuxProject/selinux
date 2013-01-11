#! /usr/bin/python -Es
# Copyright (C) 2012 Red Hat
# AUTHOR: Dan Walsh <dwalsh@redhat.com>
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
import os, sys
from sepolicy import get_os_version
import argparse
import gettext
PROGNAME="policycoreutils"
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

class CheckPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not os.path.exists(values):
                raise ValueError("%s does not exist" % values)
        setattr(namespace, self.dest, values)

class CheckType(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.network import domains

        if isinstance(values,str):
            setattr(namespace, self.dest, values)
        else:
            newval = getattr(namespace, self.dest)
            if not newval:
                newval = []

            for v in values:
                newval.append(v)
            setattr(namespace, self.dest, newval)

class CheckDomain(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.network import domains

        if isinstance(values,str):
            if values not in domains:
                raise ValueError("%s must be an SELinux process domain:\nValid domains: %s" % (values, ", ".join(domains)))
            setattr(namespace, self.dest, values)
        else:
            newval = getattr(namespace, self.dest)
            if not newval:
                newval = []

            for v in values:
                if v not in domains:
                    raise ValueError("%s must be an SELinux process domain:\nValid domains: %s" % (v, ", ".join(domains)))
                newval.append(v)
            setattr(namespace, self.dest, newval)

all_classes = None
class CheckClass(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        import sepolicy
        global all_classes
        if not all_classes:
                all_classes = map(lambda x: x['name'], sepolicy.info(sepolicy.TCLASS))
        if values not in all_classes:
            raise ValueError("%s must be an SELinux class:\nValid classes: %s" % (values, ", ".join(all_classes)))

        setattr(namespace, self.dest, values)

class CheckAdmin(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.interface import get_admin
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        admins = get_admin()
        if values not in admins:
            raise ValueError("%s must be an SELinux admin domain:\nValid admin domains: %s" % (values, ", ".join(admins)))
        newval.append(values)
        setattr(namespace, self.dest, newval)

class CheckPort(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        for v in values:
            if v < 1 or v > 65536:
                raise ValueError("%s must be an integer between 1 and 65536" % v)
            newval.append(v)
        setattr(namespace, self.dest, newval)

class CheckPortType(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.network import port_types
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        for v in values:
            if v not in port_types:
                raise ValueError("%s must be an SELinux port type:\nValid port types: %s" % (v, ", ".join(port_types)))
            newval.append(v)
        setattr(namespace, self.dest, values)

class LoadPolicy(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        import sepolicy
        sepolicy.policy(values)
        setattr(namespace, self.dest, values)

class CheckPolicyType(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.generate import get_poltype_desc, poltype
        if values not in poltype.keys():
            raise ValueError("%s invalid SELinux policy type\n%s" % (values, get_poltype_desc()))
            newval.append(v)
        setattr(namespace, self.dest, values)

class CheckUser(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        from sepolicy import get_all_users
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        users = get_all_users()
        if value not in users:
                raise ValueError("%s must be an SELinux user:\nValid users: %s" % (value, ", ".join(users)))
        newval.append(value)
        setattr(namespace, self.dest, newval)

def _print_net(src, protocol, perm):
    from sepolicy.network import get_network_connect
    portdict = get_network_connect(src, protocol, perm)
    if len(portdict) > 0:
        print "%s: %s %s" % (src, protocol, perm)
        for p in portdict:
            for recs in portdict[p]:
                print "\t" + recs

def network(args):
    from sepolicy.network import portrecsbynum, portrecs, get_network_connect
    if args.list_ports:
        all_ports = []
        for i in portrecs:
            if i[0] not in all_ports:
                all_ports.append(i[0])
        all_ports.sort()
        print "\n".join(all_ports)

    if args.port:
        for port in args.port:
            found = False
            for i in portrecsbynum:
                if i[0] <= port and port <= i[1]:
                    if i[0] == i[1]:
                        range = i[0]
                    else:
                        range = "%s-%s" % (i[0], i[1])
                    found = True
                    print "%d: %s %s %s" % (port, i[2], portrecsbynum[i][0], range)
            if not found:
                if port < 500:
                    print "Undefined reserved port type"
                else:
                    print "Undefined port type"
    if args.type:
        for t in args.type:
            if (t,'tcp') in portrecs.keys():
                print "%s: tcp: %s" % (t, ",".join(portrecs[t,'tcp']))
            if (t,'udp') in portrecs.keys():
                print "%s: udp: %s" % (t, ",".join(portrecs[t,'udp']))
    if args.domain:
        for d in args.domain:
            _print_net(d, "tcp", "name_connect")
            for net in ("tcp", "udp"):
                _print_net(d, net, "name_bind")

def manpage(args):
    from sepolicy.manpage import ManPage, HTMLManPages, manpage_domains, manpage_roles, gen_domains

    path = args.path
    if args.policy:
        for f in ( "policy.xml", "file_context", "file_context.homedirs"):
            if not os.path.exists(path + f):
                raise ValueError("manpage creation with alternate policy requires the %s file exist" % (path + f))

    if args.all:
        test_domains = gen_domains()
    else:
        test_domains = args.domain

    for domain in test_domains:
        m = ManPage(domain, path, args.web)
        print m.get_man_page_path()

    if args.web:
        HTMLManPages(manpage_roles, manpage_domains, path, args.os)

def gen_manpage_args(parser):
        man = parser.add_parser("manpage",
                                   help=_('Generate SELinux man pages'))

        man.add_argument("-p", "--path", dest="path", default="/tmp",
                         help=_("path in which the generated SELinux man pages will be stored"))
        man.add_argument("-o", "--os", dest="os", default=get_os_version(),
                         help=_("name of the OS for man pages"))
        man.add_argument("-w", "--web", dest="web", default=False, action="store_true",
                                help=_("Generate HTML man pages structure for selected SELinux man page"))
        group = man.add_mutually_exclusive_group(required=True)
        group.add_argument("-a", "--all", dest="all", default=False,
                           action="store_true",
                           help=_("All domains"))
        group.add_argument("-d", "--domain", nargs="+",
                           action=CheckDomain,
                           help=_("Domain name(s) of man pages to be created"))
        man.set_defaults(func=manpage)

def gen_network_args(parser):
        net = parser.add_parser("network",
                                   help=_('Query SELinux policy network information'))

        group = net.add_mutually_exclusive_group(required=True)
        group.add_argument("-l", "--list", dest="list_ports",
                           action="store_true",
                            help=_("list all SELinux port types"))
        group.add_argument("-p", "--port", dest="port", default=None,
                            action=CheckPort, nargs="+", type=int,
                            help=_("show SELinux type related to the port"))
        group.add_argument("-t", "--type", dest="type", default=None,
                            action=CheckPortType,nargs="+",
                            help=_("Show ports defined for this SELinux type"))
        group.add_argument("-d", "--domain", dest="domain", default=None,
                            action=CheckDomain, nargs="+",
                            help=_("show ports to which this domain can bind and/or connect"))
        net.set_defaults(func=network)

def communicate(args):
        from sepolicy.communicate import get_types

        writable = get_types(args.source, args.tclass, args.sourceaccess.split(","))
        readable = get_types(args.target, args.tclass, args.targetaccess.split(","))
        out = list(set(writable) & set(readable))

        for t in out:
            print t

def gen_communicate_args(parser):
    comm = parser.add_parser("communicate",
                             help=_('query SELinux policy to see if domains can communicate with each other'))
    comm.add_argument("-s", "--source", dest="source",
                      action=CheckDomain, required=True,
                      help=_("Source Domain"))
    comm.add_argument("-t", "--target", dest="target",
                      action=CheckDomain, required=True,
                      help=_("Target Domain"))
    comm.add_argument("-c", "--class", required=False, dest="tclass",
                      action=CheckClass,
                      default="file", help="class to use for communications, Default 'file'")
    comm.add_argument("-S", "--sourceaccess", required=False, dest="sourceaccess",  default="open,write", help="comma separate list of permissions for the source type to use, Default 'open,write'")
    comm.add_argument("-T", "--targetaccess", required=False, dest="targetaccess",  default="open,read", help="comma separated list of permissions for the target type to use, Default 'open,read'")
    comm.set_defaults(func=communicate)

def booleans(args):
    import selinux
    from sepolicy import boolean_desc
    if args.all:
        rc, args.booleans = selinux.security_get_boolean_names()
    args.booleans.sort()

    for b in args.booleans:
        print "%s=_(\"%s\")" % (b, boolean_desc(b))

def gen_booleans_args(parser):
    bools = parser.add_parser("booleans",
                              help=_('query SELinux Policy to see description of booleans'))
    group = bools.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--all", dest="all", default=False,
                       action="store_true",
                       help=_("get all booleans descriptions"))
    group.add_argument("-b", "--boolean", dest="booleans", nargs="+",
                       help=_("boolean to get description"))
    bools.set_defaults(func=booleans)

def transition(args):
    from sepolicy.transition import setrans
    mytrans = setrans(args.source, args.target)
    mytrans.output()

def gen_transition_args(parser):
    trans = parser.add_parser("transition",
                              help=_('query SELinux Policy to see how a source process domain can transition to the target process domain'))
    trans.add_argument("-s", "--source", dest="source",
                       action=CheckDomain, required=True,
                       help=_("source process domain"))
    trans.add_argument("-t", "--target", dest="target",
                       action=CheckDomain,
                       help=_("target process domain"))
    trans.set_defaults(func=transition)

def interface(args):
    from sepolicy.interface import get_admin, get, get_user
    if args.list_admin:
        for a in get_admin():
            print a
    if args.list_user:
        for a in get_user():
            print a
    if args.list:
        for m in get():
            print m

def generate(args):
    from sepolicy.generate import policy, USERS, SANDBOX, APPLICATIONS, NEWTYPE
    cmd = None
    if args.policytype not in USERS +  [ SANDBOX, NEWTYPE]:
        if not args.command:
            raise ValueError(_("Command required for this type of policy"))
        cmd = os.path.realpath(args.command)
        if not args.name:
            args.name = os.path.basename(cmd).replace("-","_")

    mypolicy = policy(args.name, args.policytype)
    if cmd:
        mypolicy.set_program(cmd)

    if args.types:
        mypolicy.set_types(args.types)

    for p in args.writepaths:
        if os.path.isdir(p):
            mypolicy.add_dir(p)
        else:
            mypolicy.add_file(p)

    mypolicy.set_transition_users(args.user)
    mypolicy.set_admin_domains(args.admin_domain)
    mypolicy.set_existing_domains(args.domain)

    if args.policytype in APPLICATIONS:
        mypolicy.gen_writeable()
        mypolicy.gen_symbols()
    print mypolicy.generate(args.path)

def gen_interface_args(parser):
    itf = parser.add_parser("interface",
                            help=_('List SELinux Policy interfaces'))
    group = itf.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--list_admin", dest="list_admin",action="store_true",                       default=False,
                       help="List all domains with admin interface")
    group.add_argument("-u", "--list_user", dest="list_user",action="store_true",
                       default=False,
                       help="List all domains with SELinux user role interface")
    group.add_argument("-l", "--list", dest="list",action="store_true",
                       default=False,
                       help="List all interfaces")
    itf.set_defaults(func=interface)

def gen_generate_args(parser):
    from sepolicy.generate import DAEMON, get_poltype_desc, poltype, DAEMON, DBUS, INETD, CGI, SANDBOX, USER, EUSER, TUSER, XUSER, LUSER, AUSER, RUSER, NEWTYPE
    pol = parser.add_parser("generate",
                            help=_('Generate SELinux Policy module template'))
    pol.add_argument("-d", "--domain", dest="domain", default=[],
                     action=CheckDomain, nargs="*",
                     help=_("Enter domain type which you will be extending"))
    pol.add_argument("-u", "--user", dest="user", default=[],
                     action=CheckUser, 
                     help=_("Enter SELinux user(s) which will transition to this domain"))
    pol.add_argument("-a", "--admin", dest="admin_domain",default=[],
                     action=CheckAdmin,
                     help=_("Enter domain(s) that this confined admin will administrate"))
    pol.add_argument("-n", "--name", dest="name",
                     default=None,
                     help=_("name of policy to generate"))
    pol.add_argument("-T", "--test", dest="test", default=False, action="store_true",
                     help=argparse.SUPPRESS)
    pol.add_argument("-t", "--type", dest="types", default=[], nargs="*",
                     action=CheckType, 
                     help=argparse.SUPPRESS)
    pol.add_argument("-p", "--path", dest="path", default=os.getcwd(),
                     help=_("path in which the generated policy files will be stored"))
    pol.add_argument("-w", "--writepath", dest="writepaths", nargs="*", default = [],
                     help=_("path to which the confined processes will need to write"))
    pol.add_argument("command",nargs="?", default=None,
                     help=_("executable to confine"))
    group = pol.add_mutually_exclusive_group(required=False)
    group.add_argument("--newtype", dest="policytype", const=NEWTYPE,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[NEWTYPE])
    group.add_argument("--admin_user", dest="policytype", const=AUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[AUSER])
    group.add_argument("--application", dest="policytype", const=USER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[USER])
    group.add_argument("--cgi", dest="policytype", const=CGI,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[CGI])
    group.add_argument("--confined_admin", dest="policytype", const=RUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[RUSER])
    group.add_argument("--customize", dest="policytype", const=EUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[EUSER])
    group.add_argument("--dbus", dest="policytype", const=DBUS, 
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[DBUS])
    group.add_argument("--desktop_user", dest="policytype", const=LUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[LUSER])
    group.add_argument("--inetd", dest="policytype", const=INETD,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[INETD])
    group.add_argument("--init", dest="policytype", const=DAEMON, 
                       action="store_const", default=DAEMON, 
                       help=_("Generate Policy for %s") % poltype[DAEMON])
    group.add_argument("--sandbox", dest="policytype", const=SANDBOX,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[SANDBOX])
    group.add_argument("--term_user", dest="policytype", const=TUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[TUSER])
    group.add_argument("--x_user", dest="policytype", const=XUSER,
                       action="store_const",
                       help=_("Generate Policy for %s") % poltype[XUSER])
    pol.set_defaults(func=generate)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SELinux Policy Inspection Tool')
    subparsers = parser.add_subparsers(help=_("commands"))
    parser.add_argument("-P", "--policy", dest="policy",
                        action=LoadPolicy,
                        default=None, help=_("Alternate SELinux policy, defaults to /sys/fs/selinux/policy"))
    gen_booleans_args(subparsers)
    gen_communicate_args(subparsers)
    gen_generate_args(subparsers)
    gen_interface_args(subparsers)
    gen_manpage_args(subparsers)
    gen_network_args(subparsers)
    gen_transition_args(subparsers)

    try:
        args = parser.parse_args()
        args.func(args)
        sys.exit(0)
    except ValueError,e:
        sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
