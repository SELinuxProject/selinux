#!/usr/bin/python3 -EsI
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
import os
import sys
import selinux
import sepolicy
import multiprocessing
from sepolicy import get_os_version, get_conditionals, get_conditionals_format_text
import argparse
PROGNAME = "selinux-python"
try:
    import gettext
    kwargs = {}
    if sys.version_info < (3,):
        kwargs['unicode'] = True
    t = gettext.translation(PROGNAME,
                    localedir="/usr/share/locale",
                    **kwargs,
                    fallback=True)
    _ = t.gettext
except:
    try:
        import builtins
        builtins.__dict__['_'] = str
    except ImportError:
        import __builtin__
        __builtin__.__dict__['_'] = unicode

usage = "sepolicy generate [-h] [-n NAME] [-p PATH] ["
usage_dict = {' --newtype': ('-t [TYPES [TYPES ...]]',), ' --customize': ('-d DOMAIN', '-a  ADMIN_DOMAIN', "[ -w WRITEPATHS ]",), ' --admin_user': ('[-r TRANSITION_ROLE ]', "[ -w WRITEPATHS ]",), ' --application': ('COMMAND', "[ -w WRITEPATHS ]",), ' --cgi': ('COMMAND', "[ -w WRITEPATHS ]",), ' --confined_admin': ('-a  ADMIN_DOMAIN', "[ -w WRITEPATHS ]",), ' --dbus': ('COMMAND', "[ -w WRITEPATHS ]",), ' --desktop_user': ('', "[ -w WRITEPATHS ]",), ' --inetd': ('COMMAND', "[ -w WRITEPATHS ]",), ' --init': ('COMMAND', "[ -w WRITEPATHS ]",), ' --sandbox': ("[ -w WRITEPATHS ]",), ' --term_user': ("[ -w WRITEPATHS ]",), ' --x_user': ("[ -w WRITEPATHS ]",)}


class CheckPath(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        if not os.path.exists(values):
            raise ValueError("%s does not exist" % values)
        setattr(namespace, self.dest, values)


class CheckType(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        if isinstance(values, str):
            setattr(namespace, self.dest, values)
        else:
            newval = getattr(namespace, self.dest)
            if not newval:
                newval = []

            for v in values:
                newval.append(v)
            setattr(namespace, self.dest, newval)


class CheckBoolean(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        booleans = sepolicy.get_all_booleans()
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []

        if isinstance(values, str):
            v = selinux.selinux_boolean_sub(values)
            if v not in booleans:
                raise ValueError("%s must be an SELinux process domain:\nValid domains: %s" % (v, ", ".join(booleans)))
            newval.append(v)
            setattr(namespace, self.dest, newval)
        else:
            for value in values:
                v = selinux.selinux_boolean_sub(value)
                if v not in booleans:
                    raise ValueError("%s must be an SELinux boolean:\nValid boolean: %s" % (v, ", ".join(booleans)))
                newval.append(v)
            setattr(namespace, self.dest, newval)


class CheckDomain(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        domains = sepolicy.get_all_domains()

        if isinstance(values, str):
            values = sepolicy.get_real_type_name(values)
            if values not in domains:
                raise ValueError("%s must be an SELinux process domain:\nValid domains: %s" % (values, ", ".join(domains)))
            setattr(namespace, self.dest, values)
        else:
            newval = getattr(namespace, self.dest)
            if not newval:
                newval = []

            for v in values:
                v = sepolicy.get_real_type_name(v)
                if v not in domains:
                    raise ValueError("%s must be an SELinux process domain:\nValid domains: %s" % (v, ", ".join(domains)))
                newval.append(v)
            setattr(namespace, self.dest, newval)

all_classes = None


class CheckClass(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
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
        port_types = sepolicy.get_all_port_types()
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        for v in values:
            v = sepolicy.get_real_type_name(v)
            if v not in port_types:
                raise ValueError("%s must be an SELinux port type:\nValid port types: %s" % (v, ", ".join(port_types)))
            newval.append(v)
        setattr(namespace, self.dest, newval)


class LoadPolicy(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        import sepolicy
        sepolicy.policy(values)
        setattr(namespace, self.dest, values)


class CheckUser(argparse.Action):

    def __call__(self, parser, namespace, value, option_string=None):
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        users = sepolicy.get_all_users()
        if value not in users:
            raise ValueError("%s must be an SELinux user:\nValid users: %s" % (value, ", ".join(users)))
        newval.append(value)
        setattr(namespace, self.dest, newval)


class CheckRole(argparse.Action):

    def __call__(self, parser, namespace, value, option_string=None):
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        roles = sepolicy.get_all_roles()
        if value not in roles:
            raise ValueError("%s must be an SELinux role:\nValid roles: %s" % (value, ", ".join(roles)))
        newval.append(value[:-2])
        setattr(namespace, self.dest, newval)


class InterfaceInfo(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        from sepolicy.interface import get_interface_dict
        interface_dict = get_interface_dict()
        for v in values:
            if v not in interface_dict.keys():
                raise ValueError(_("Interface %s does not exist.") % v)

        setattr(namespace, self.dest, values)


def generate_custom_usage(usage_text, usage_dict):
    sorted_keys = []
    for i in usage_dict.keys():
        sorted_keys.append(i)
    sorted_keys.sort()
    for k in sorted_keys:
        usage_text += "%s %s |" % (k, (" ".join(usage_dict[k])))
    usage_text = usage_text[:-1] + "]"
    usage_text = _(usage_text)

    return usage_text

# expects formats:
# "22 (sshd_t)", "80, 8080 (httpd_t)", "all ports (port_type)"
def port_string_to_num(val):
    try:
        return int(val.split(" ")[0].split(",")[0].split("-")[0])
    except:
        return 99999999


def _print_net(src, protocol, perm):
    import sepolicy.network
    portdict = sepolicy.network.get_network_connect(src, protocol, perm)
    if len(portdict) > 0:
        bold_start = "\033[1m"
        bold_end = "\033[0;0m"
        print("\n" + bold_start + "%s: %s %s" % (src, protocol, perm) + bold_end)
        port_strings = []
        boolean_text = ""
        for p in portdict:
            for t, recs in portdict[p]:
                cond = get_conditionals(src, t, "%s_socket" % protocol, [perm])
                if cond:
                    boolean_text = get_conditionals_format_text(cond)
                    port_strings.append("%s (%s) %s" % (", ".join(recs), t, boolean_text))
                else:
                    port_strings.append("%s (%s)" % (", ".join(recs), t))
        port_strings.sort(key=lambda param: port_string_to_num(param))
        for p in port_strings:
            print("\t" + p)


def network(args):
    portrecs, portrecsbynum = sepolicy.gen_port_dict()
    all_ports = []
    if args.list_ports:
        for i in portrecs:
            if i[0] not in all_ports:
                all_ports.append(i[0])
        all_ports.sort()
        print("\n".join(all_ports))

    for port in args.port:
        found = False
        for i in portrecsbynum:
            if i[0] <= port and port <= i[1]:
                if i[0] == i[1]:
                    range = i[0]
                else:
                    range = "%s-%s" % (i[0], i[1])
                found = True
                print("%d: %s %s %s" % (port, i[2], portrecsbynum[i][0], range))
        if not found:
            if port < 500:
                print("Undefined reserved port type")
            else:
                print("Undefined port type")

    for t in args.type:
        if (t, 'tcp') in portrecs.keys():
            print("%s: tcp: %s" % (t, ",".join(portrecs[t, 'tcp'])))
        if (t, 'udp') in portrecs.keys():
            print( "%s: udp: %s" % (t, ",".join(portrecs[t, 'udp'])))

    for a in args.applications:
        d = sepolicy.get_init_transtype(a)
        if d:
            args.domain.append(d)

    for d in args.domain:
        _print_net(d, "tcp", "name_connect")
        for net in ("tcp", "udp"):
            _print_net(d, net, "name_bind")


def gui_run(args):
    try:
        import sepolicy.gui
        sepolicy.gui.SELinuxGui(args.domain, args.test)
        pass
    except ImportError:
        raise ValueError(_("You need to install policycoreutils-gui package to use the gui option"))


def gen_gui_args(parser):
    gui = parser.add_parser("gui",
                            help=_('Graphical User Interface for SELinux Policy'))
    gui.add_argument("-d", "--domain", default=None,
                     action=CheckDomain,
                     help=_("Domain name(s) of man pages to be created"))
    gui.add_argument("-t", "--test", default=False, action="store_true",
                     help=argparse.SUPPRESS)
    gui.set_defaults(func=gui_run)


def manpage_work(domain, path, root, source_files, web):
    from sepolicy.manpage import ManPage
    m = ManPage(domain, path, root, source_files, web)
    print(m.get_man_page_path())
    return (m.manpage_domains, m.manpage_roles)

def manpage(args):
    from sepolicy.manpage import HTMLManPages, gen_domains

    path = args.path
    if not args.policy and args.root != "/":
        sepolicy.policy(sepolicy.get_installed_policy(args.root))
    if args.source_files and args.root == "/":
        raise ValueError(_("Alternative root needs to be setup"))

    if args.all:
        test_domains = gen_domains()
    else:
        test_domains = args.domain

    manpage_domains = set()
    manpage_roles = set()
    multiprocessing.set_start_method('fork')
    p = multiprocessing.Pool()
    async_results = []
    for domain in test_domains:
        async_results.append(p.apply_async(manpage_work, [domain, path, args.root, args.source_files, args.web]))
    for result in async_results:
        domains, roles = result.get()
        manpage_domains.update(domains)
        manpage_roles.update(roles)

    p.close()
    p.join()

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
    man.add_argument("-r", "--root", dest="root", default="/",
                     help=_("Alternate root directory, defaults to /"))
    man.add_argument("--source_files", dest="source_files", default=False, action="store_true",
                     help=_("With this flag, alternative root path needs to include file context files and policy.xml file"))
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
    group.add_argument("-p", "--port", dest="port", default=[],
                       action=CheckPort, nargs="+", type=int,
                       help=_("show SELinux type related to the port"))
    group.add_argument("-t", "--type", dest="type", default=[],
                       action=CheckPortType, nargs="+",
                       help=_("Show ports defined for this SELinux type"))
    group.add_argument("-d", "--domain", dest="domain", default=[],
                       action=CheckDomain, nargs="+",
                       help=_("show ports to which this domain can bind and/or connect"))
    group.add_argument("-a", "--application", dest="applications", default=[],
                       nargs="+",
                       help=_("show ports to which this application can bind and/or connect"))
    net.set_defaults(func=network)


def communicate(args):
    from sepolicy.communicate import get_types

    writable = get_types(args.source, args.tclass, args.sourceaccess.split(","))
    readable = get_types(args.target, args.tclass, args.targetaccess.split(","))
    out = list(set(writable) & set(readable))

    for t in out:
        print(t)


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
    comm.add_argument("-S", "--sourceaccess", required=False, dest="sourceaccess", default="open,write", help="comma separate list of permissions for the source type to use, Default 'open,write'")
    comm.add_argument("-T", "--targetaccess", required=False, dest="targetaccess", default="open,read", help="comma separated list of permissions for the target type to use, Default 'open,read'")
    comm.set_defaults(func=communicate)


def booleans(args):
    from sepolicy import boolean_desc
    if args.all:
        rc, args.booleans = selinux.security_get_boolean_names()
    args.booleans.sort()

    for b in args.booleans:
        print("%s=_(\"%s\")" % (b, boolean_desc(b)))


def gen_booleans_args(parser):
    bools = parser.add_parser("booleans",
                              help=_('query SELinux Policy to see description of booleans'))
    group = bools.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--all", dest="all", default=False,
                       action="store_true",
                       help=_("get all booleans descriptions"))
    group.add_argument("-b", "--boolean", dest="booleans", nargs="+",
                       action=CheckBoolean, required=False,
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


def print_interfaces(interfaces, args, append=""):
    from sepolicy.interface import get_interface_format_text, interface_compile_test
    for i in interfaces:
        if args.verbose:
            try:
                print(get_interface_format_text(i + append))
            except KeyError:
                print(i)
        if args.compile:
            try:
                interface_compile_test(i)
            except KeyError:
                print(i)
        else:
            print(i)


def interface(args):
    from sepolicy.interface import get_admin, get_user, get_interface_dict, get_all_interfaces
    if args.list_admin:
        print_interfaces(get_admin(args.file), args, "_admin")
    if args.list_user:
        print_interfaces(get_user(args.file), args, "_role")
    if args.list:
        print_interfaces(get_all_interfaces(args.file), args)
    if args.interfaces:
        print_interfaces(args.interfaces, args)


def generate(args):
    from sepolicy.generate import policy, AUSER, RUSER, EUSER, USERS, SANDBOX, APPLICATIONS, NEWTYPE
    cmd = None
# numbers present POLTYPE defined in sepolicy.generate
    conflict_args = {'TYPES': (NEWTYPE,), 'DOMAIN': (EUSER,), 'ADMIN_DOMAIN': (AUSER, RUSER, EUSER,)}
    error_text = ""

    if args.policytype is None:
        generate_usage = generate_custom_usage(usage, usage_dict)
        for k in usage_dict:
            error_text += "%s" % (k)
        print(generate_usage)
        print(_("sepolicy generate: error: one of the arguments %s is required") % error_text)
        sys.exit(1)

    if args.policytype in APPLICATIONS:
        if not args.command:
            raise ValueError(_("Command required for this type of policy"))
        cmd = os.path.realpath(args.command)
        if not args.name:
            args.name = os.path.basename(cmd).replace("-", "_")

    mypolicy = policy(args.name, args.policytype)
    if cmd:
        mypolicy.set_program(cmd)

    if args.types:
        if args.policytype not in conflict_args['TYPES']:
            raise ValueError(_("-t option can not be used with '%s' domains. Read usage for more details.") % sepolicy.generate.poltype[args.policytype])
        mypolicy.set_types(args.types)

    if args.domain:
        if args.policytype not in conflict_args['DOMAIN']:
            raise ValueError(_("-d option can not be used with '%s' domains. Read usage for more details.") % sepolicy.generate.poltype[args.policytype])

    if args.admin_domain:
        if args.policytype not in conflict_args['ADMIN_DOMAIN']:
            raise ValueError(_("-a option can not be used with '%s' domains. Read usage for more details.") % sepolicy.generate.poltype[args.policytype])

    if len(args.writepaths) > 0 and args.policytype == NEWTYPE:

        raise ValueError(_("-w option can not be used with the --newtype option"))

    for p in args.writepaths:
        if os.path.isdir(p):
            mypolicy.add_dir(p)
        else:
            mypolicy.add_file(p)

    mypolicy.set_transition_users(args.user)
    mypolicy.set_admin_roles(args.role)
    mypolicy.set_admin_domains(args.admin_domain)
    mypolicy.set_existing_domains(args.domain)

    if args.policytype in APPLICATIONS:
        mypolicy.gen_writeable()
        mypolicy.gen_symbols()
    print(mypolicy.generate(args.path))


def gen_interface_args(parser):
    itf = parser.add_parser("interface",
                            help=_('List SELinux Policy interfaces'))
    itf.add_argument("-c", "--compile", dest="compile",
                     action="store_true", default=False,
                     help="Run compile test for selected interface")
    itf.add_argument("-v", "--verbose", dest="verbose",
                     action="store_true", default=False,
                     help="Show verbose information")
    itf.add_argument("-f", "--file", dest="file",
                     help="Interface file")
    group = itf.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--list_admin", dest="list_admin", action="store_true", default=False,
                       help="List all domains with admin interface - DOMAIN_admin()")
    group.add_argument("-u", "--list_user", dest="list_user", action="store_true",
                       default=False,
                       help="List all domains with SELinux user role interface - DOMAIN_role()")
    group.add_argument("-l", "--list", dest="list", action="store_true",
                       default=False,
                       help="List all interfaces")
    group.add_argument("-i", "--interfaces", nargs="+", dest="interfaces",
                       action=InterfaceInfo,
                       help=_("Enter interface names, you wish to query"))
    itf.set_defaults(func=interface)


def gen_generate_args(parser):
    from sepolicy.generate import get_poltype_desc, poltype, DAEMON, DBUS, INETD, CGI, SANDBOX, USER, EUSER, TUSER, XUSER, LUSER, AUSER, RUSER, NEWTYPE

    generate_usage = generate_custom_usage(usage, usage_dict)

    pol = parser.add_parser("generate", usage=generate_usage,
                            help=_('Generate SELinux Policy module template'))
    pol.add_argument("-d", "--domain", dest="domain", default=[],
                     action=CheckDomain, nargs="*",
                     help=_("Enter domain type which you will be extending"))
    pol.add_argument("-u", "--user", dest="user", default=[],
                     action=CheckUser,
                     help=_("Enter SELinux user(s) which will transition to this domain"))
    pol.add_argument("-r", "--role", dest="role", default=[],
                     action=CheckRole,
                     help=_("Enter SELinux role(s) to which the administror domain will transition"))
    pol.add_argument("-a", "--admin", dest="admin_domain", default=[],
                     action=CheckAdmin,
                     help=_("Enter domain(s) which this confined admin will administrate"))
    pol.add_argument("-n", "--name", dest="name",
                     default=None,
                     help=_("name of policy to generate"))
    pol.add_argument("-T", "--test", dest="test", default=False, action="store_true",
                     help=argparse.SUPPRESS)
    pol.add_argument("-t", "--type", dest="types", default=[], nargs="*",
                     action=CheckType,
                     help="Enter type(s) for which you will generate new definition and rule(s)")
    pol.add_argument("-p", "--path", dest="path", default=os.getcwd(),
                     help=_("path in which the generated policy files will be stored"))
    pol.add_argument("-w", "--writepath", dest="writepaths", nargs="*", default=[],
                     help=_("path to which the confined processes will need to write"))
    cmdtype = pol.add_argument_group(_("Policy types which require a command"))
    cmdgroup = cmdtype.add_mutually_exclusive_group(required=False)
    cmdgroup.add_argument("--application", dest="policytype", const=USER,
                          action="store_const",
                          help=_("Generate '%s' policy") % poltype[USER])
    cmdgroup.add_argument("--cgi", dest="policytype", const=CGI,
                          action="store_const",
                          help=_("Generate '%s' policy") % poltype[CGI])
    cmdgroup.add_argument("--dbus", dest="policytype", const=DBUS,
                          action="store_const",
                          help=_("Generate '%s' policy") % poltype[DBUS])
    cmdgroup.add_argument("--inetd", dest="policytype", const=INETD,
                          action="store_const",
                          help=_("Generate '%s' policy") % poltype[INETD])
    cmdgroup.add_argument("--init", dest="policytype", const=DAEMON,
                          action="store_const", default=DAEMON,
                          help=_("Generate '%s' policy") % poltype[DAEMON])

    type = pol.add_argument_group("Policy types which do not require a command")
    group = type.add_mutually_exclusive_group(required=False)
    group.add_argument("--admin_user", dest="policytype", const=AUSER,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[AUSER])
    group.add_argument("--confined_admin", dest="policytype", const=RUSER,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[RUSER])
    group.add_argument("--customize", dest="policytype", const=EUSER,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[EUSER])
    group.add_argument("--desktop_user", dest="policytype", const=LUSER,
                       action="store_const",
                       help=_("Generate '%s' policy ") % poltype[LUSER])
    group.add_argument("--newtype", dest="policytype", const=NEWTYPE,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[NEWTYPE])
    group.add_argument("--sandbox", dest="policytype", const=SANDBOX,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[SANDBOX])
    group.add_argument("--term_user", dest="policytype", const=TUSER,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[TUSER])
    group.add_argument("--x_user", dest="policytype", const=XUSER,
                       action="store_const",
                       help=_("Generate '%s' policy") % poltype[XUSER])
    pol.add_argument("command", nargs="?", default=None,
                     help=_("executable to confine"))
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
    gen_gui_args(subparsers)
    gen_interface_args(subparsers)
    gen_manpage_args(subparsers)
    gen_network_args(subparsers)
    gen_transition_args(subparsers)

    try:
        if os.path.basename(sys.argv[0]) == "sepolgen":
            parser_args = [ "generate" ] + sys.argv[1:]
        elif len(sys.argv) > 1:
            parser_args = sys.argv[1:]
        else:
            parser_args = ["-h"]
        args = parser.parse_args(args=parser_args)
        args.func(args)
        sys.exit(0)
    except ValueError as e:
        sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
        sys.exit(1)
    except IOError as e:
        sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
        sys.exit(1)
    except KeyboardInterrupt:
        print("Out")
        sys.exit(0)
