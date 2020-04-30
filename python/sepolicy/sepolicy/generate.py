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
import os
import sys
import stat
import re
import sepolicy
from sepolicy import get_all_types, get_all_attributes, get_all_roles
import time

from .templates import executable
from .templates import boolean
from .templates import etc_rw
from .templates import unit_file
from .templates import var_cache
from .templates import var_spool
from .templates import var_lib
from .templates import var_log
from .templates import var_run
from .templates import tmp
from .templates import rw
from .templates import network
from .templates import script
from .templates import spec
from .templates import user
import sepolgen.interfaces as interfaces
import sepolgen.defaults as defaults

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


def get_rpm_nvr_from_header(hdr):
    'Given an RPM header return the package NVR as a string'
    name = hdr['name']
    version = hdr['version']
    release = hdr['release']
    release_version = version + "-" + release.split(".")[0]
    os_version = release.split(".")[1]

    return [name, release_version, os_version]


def get_rpm_nvr_list(package):
    try:
        import rpm
        nvr = None
        ts = rpm.ts()
        mi = ts.dbMatch(rpm.RPMTAG_NAME, package)
        for h in mi:
            nvr = get_rpm_nvr_from_header(h)
            break
    except:
        print(("Failed to retrieve rpm info for %s") % package)
        nvr = None

    return nvr


def get_all_ports():
    dict = {}
    for p in sepolicy.info(sepolicy.PORT):
        if p['type'] == "reserved_port_t" or \
                p['type'] == "port_t" or \
                p['type'] == "hi_reserved_port_t":
            continue
        dict[(p['low'], p['high'], p['protocol'])] = (p['type'], p.get('range'))
    return dict


def get_all_users():
    users = [x['name'] for x in sepolicy.info(sepolicy.USER)]
    users.remove("system_u")
    users.remove("root")
    users.sort()
    return users

ALL = 0
RESERVED = 1
UNRESERVED = 2
PORTS = 3
ADMIN_TRANSITION_INTERFACE = "_admin$"
USER_TRANSITION_INTERFACE = "_role$"

DAEMON = 0
DBUS = 1
INETD = 2
CGI = 3
SANDBOX = 4
USER = 5
EUSER = 6
TUSER = 7
XUSER = 8
LUSER = 9
AUSER = 10
RUSER = 11
NEWTYPE = 12

poltype = {}
poltype[DAEMON] = _("Standard Init Daemon")
poltype[DBUS] = _("DBUS System Daemon")
poltype[INETD] = _("Internet Services Daemon")
poltype[CGI] = _("Web Application/Script (CGI)")
poltype[SANDBOX] = _("Sandbox")
poltype[USER] = _("User Application")
poltype[EUSER] = _("Existing Domain Type")
poltype[TUSER] = _("Minimal Terminal Login User Role")
poltype[XUSER] = _("Minimal X Windows Login User Role")
poltype[LUSER] = _("Desktop Login User Role")
poltype[AUSER] = _("Administrator Login User Role")
poltype[RUSER] = _("Confined Root Administrator Role")
poltype[NEWTYPE] = _("Module information for a new type")


def get_poltype_desc():
    keys = poltype.keys()
    keys.sort()
    msg = _("Valid Types:\n")
    for k in keys:
        msg += "%2s: %s\n" % (k, poltype[k])
    return msg

APPLICATIONS = [DAEMON, DBUS, INETD, USER, CGI]
USERS = [XUSER, TUSER, LUSER, AUSER, RUSER]


def verify_ports(ports):
    if ports == "":
        return []
    max_port = 2 ** 16
    try:
        temp = []
        for a in ports.split(","):
            r = a.split("-")
            if len(r) > 2:
                raise ValueError
            if len(r) == 1:
                begin = int(r[0])
                end = int(r[0])
            else:
                begin = int(r[0])
                end = int(r[1])

                if begin > end:
                    raise ValueError

            for p in range(begin, end + 1):
                if p < 1 or p > max_port:
                    raise ValueError
                temp.append(p)
        return temp
    except ValueError:
        raise ValueError(_("Ports must be numbers or ranges of numbers from 1 to %d ") % max_port)


class policy:

    def __init__(self, name, type):
        self.rpms = []
        self.ports = {}
        self.all_roles = get_all_roles()
        self.types = []

        if type not in poltype:
            raise ValueError(_("You must enter a valid policy type"))

        if not name:
            raise ValueError(_("You must enter a name for your policy module for your '%s'.") % poltype[type])
        try:
            self.ports = get_all_ports()
        except ValueError as e:
            print("Can not get port types, must be root for this information")
        except RuntimeError as e:
            print("Can not get port types", e)

        self.symbols = {}
        self.symbols["openlog"] = "set_use_kerberos(True)"
        self.symbols["openlog"] = "set_use_kerb_rcache(True)"
        self.symbols["openlog"] = "set_use_syslog(True)"
        self.symbols["gethostby"] = "set_use_resolve(True)"
        self.symbols["getaddrinfo"] = "set_use_resolve(True)"
        self.symbols["getnameinfo"] = "set_use_resolve(True)"
        self.symbols["krb"] = "set_use_kerberos(True)"
        self.symbols["gss_accept_sec_context"] = "set_manage_krb5_rcache(True)"
        self.symbols["krb5_verify_init_creds"] = "set_manage_krb5_rcache(True)"
        self.symbols["krb5_rd_req"] = "set_manage_krb5_rcache(True)"
        self.symbols["__syslog_chk"] = "set_use_syslog(True)"
        self.symbols["getpwnam"] = "set_use_uid(True)"
        self.symbols["getpwuid"] = "set_use_uid(True)"
        self.symbols["dbus_"] = "set_use_dbus(True)"
        self.symbols["pam_"] = "set_use_pam(True)"
        self.symbols["pam_"] = "set_use_audit(True)"
        self.symbols["fork"] = "add_process('fork')"
        self.symbols["transition"] = "add_process('transition')"
        self.symbols["sigchld"] = "add_process('sigchld')"
        self.symbols["sigkill"] = "add_process('sigkill')"
        self.symbols["sigstop"] = "add_process('sigstop')"
        self.symbols["signull"] = "add_process('signull')"
        self.symbols["ptrace"] = "add_process('ptrace')"
        self.symbols["getsched"] = "add_process('getsched')"
        self.symbols["setsched"] = "add_process('setsched')"
        self.symbols["getsession"] = "add_process('getsession')"
        self.symbols["getpgid"] = "add_process('getpgid')"
        self.symbols["setpgid"] = "add_process('setpgid')"
        self.symbols["getcap"] = "add_process('getcap')"
        self.symbols["setcap"] = "add_process('setcap')"
        self.symbols["share"] = "add_process('share')"
        self.symbols["getattr"] = "add_process('getattr')"
        self.symbols["setexec"] = "add_process('setexec')"
        self.symbols["setfscreate"] = "add_process('setfscreate')"
        self.symbols["noatsecure"] = "add_process('noatsecure')"
        self.symbols["siginh"] = "add_process('siginh')"
        self.symbols["kill"] = "add_process('signal_perms')"
        self.symbols["setrlimit"] = "add_process('setrlimit')"
        self.symbols["rlimitinh"] = "add_process('rlimitinh')"
        self.symbols["dyntransition"] = "add_process('dyntransition')"
        self.symbols["setcurrent"] = "add_process('setcurrent')"
        self.symbols["execmem"] = "add_process('execmem')"
        self.symbols["execstack"] = "add_process('execstack')"
        self.symbols["execheap"] = "add_process('execheap')"
        self.symbols["setkeycreate"] = "add_process('setkeycreate')"
        self.symbols["setsockcreate"] = "add_process('setsockcreate')"

        self.symbols["chown"] = "add_capability('chown')"
        self.symbols["dac_override"] = "add_capability('dac_override')"
        self.symbols["dac_read_search"] = "add_capability('dac_read_search')"
        self.symbols["fowner"] = "add_capability('fowner')"
        self.symbols["fsetid"] = "add_capability('fsetid')"
        self.symbols["setgid"] = "add_capability('setgid')"
        self.symbols["setegid"] = "add_capability('setgid')"
        self.symbols["setresgid"] = "add_capability('setgid')"
        self.symbols["setregid"] = "add_capability('setgid')"
        self.symbols["setresuid"] = "add_capability('setuid')"
        self.symbols["setuid"] = "add_capability('setuid')"
        self.symbols["seteuid"] = "add_capability('setuid')"
        self.symbols["setreuid"] = "add_capability('setuid')"
        self.symbols["setresuid"] = "add_capability('setuid')"
        self.symbols["setpcap"] = "add_capability('setpcap')"
        self.symbols["linux_immutable"] = "add_capability('linux_immutable')"
        self.symbols["net_bind_service"] = "add_capability('net_bind_service')"
        self.symbols["net_broadcast"] = "add_capability('net_broadcast')"
        self.symbols["net_admin"] = "add_capability('net_admin')"
        self.symbols["net_raw"] = "add_capability('net_raw')"
        self.symbols["ipc_lock"] = "add_capability('ipc_lock')"
        self.symbols["ipc_owner"] = "add_capability('ipc_owner')"
        self.symbols["sys_module"] = "add_capability('sys_module')"
        self.symbols["sys_rawio"] = "add_capability('sys_rawio')"
        self.symbols["chroot"] = "add_capability('sys_chroot')"
        self.symbols["sys_chroot"] = "add_capability('sys_chroot')"
        self.symbols["sys_ptrace"] = "add_capability('sys_ptrace')"
        self.symbols["sys_pacct"] = "add_capability('sys_pacct')"
        self.symbols["mount"] = "add_capability('sys_admin')"
        self.symbols["unshare"] = "add_capability('sys_admin')"
        self.symbols["sys_admin"] = "add_capability('sys_admin')"
        self.symbols["sys_boot"] = "add_capability('sys_boot')"
        self.symbols["sys_nice"] = "add_capability('sys_nice')"
        self.symbols["sys_resource"] = "add_capability('sys_resource')"
        self.symbols["sys_time"] = "add_capability('sys_time')"
        self.symbols["sys_tty_config"] = "add_capability('sys_tty_config')"
        self.symbols["mknod"] = "add_capability('mknod')"
        self.symbols["lease"] = "add_capability('lease')"
        self.symbols["audit_write"] = "add_capability('audit_write')"
        self.symbols["audit_control"] = "add_capability('audit_control')"
        self.symbols["setfcap"] = "add_capability('setfcap')"

        self.DEFAULT_DIRS = {}
        self.DEFAULT_DIRS["/etc"] = ["etc_rw", [], etc_rw]
        self.DEFAULT_DIRS["/tmp"] = ["tmp", [], tmp]
        self.DEFAULT_DIRS["rw"] = ["rw", [], rw]
        self.DEFAULT_DIRS["/usr/lib/systemd/system"] = ["unit_file", [], unit_file]
        self.DEFAULT_DIRS["/lib/systemd/system"] = ["unit_file", [], unit_file]
        self.DEFAULT_DIRS["/etc/systemd/system"] = ["unit_file", [], unit_file]
        self.DEFAULT_DIRS["/var/cache"] = ["var_cache", [], var_cache]
        self.DEFAULT_DIRS["/var/lib"] = ["var_lib", [], var_lib]
        self.DEFAULT_DIRS["/var/log"] = ["var_log", [], var_log]
        self.DEFAULT_DIRS["/var/run"] = ["var_run", [], var_run]
        self.DEFAULT_DIRS["/var/spool"] = ["var_spool", [], var_spool]

        self.DEFAULT_EXT = {}
        self.DEFAULT_EXT["_tmp_t"] = tmp
        self.DEFAULT_EXT["_unit_file_t"] = unit_file
        self.DEFAULT_EXT["_var_cache_t"] = var_cache
        self.DEFAULT_EXT["_var_lib_t"] = var_lib
        self.DEFAULT_EXT["_var_log_t"] = var_log
        self.DEFAULT_EXT["_var_run_t"] = var_run
        self.DEFAULT_EXT["_var_spool_t"] = var_spool
        self.DEFAULT_EXT["_port_t"] = network

        self.DEFAULT_KEYS = ["/etc", "/var/cache", "/var/log", "/tmp", "rw", "/var/lib", "/var/run", "/var/spool", "/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]

        self.DEFAULT_TYPES = (
            (self.generate_daemon_types, self.generate_daemon_rules),
            (self.generate_dbusd_types, self.generate_dbusd_rules),
            (self.generate_inetd_types, self.generate_inetd_rules),
            (self.generate_cgi_types, self.generate_cgi_rules),
            (self.generate_sandbox_types, self.generate_sandbox_rules),
            (self.generate_userapp_types, self.generate_userapp_rules),
            (self.generate_existing_user_types, self.generate_existing_user_rules),
            (self.generate_min_login_user_types, self.generate_login_user_rules),
            (self.generate_x_login_user_types, self.generate_x_login_user_rules),
            (self.generate_login_user_types, self.generate_login_user_rules),
            (self.generate_admin_user_types, self.generate_login_user_rules),
            (self.generate_root_user_types, self.generate_root_user_rules),
            (self.generate_new_types, self.generate_new_rules))
        if not re.match(r"^[a-zA-Z0-9-_]+$", name):
            raise ValueError(_("Name must be alphanumeric with no spaces. Consider using option \"-n MODULENAME\""))

        if type == CGI:
            self.name = "httpd_%s_script" % name
        else:
            self.name = name

        self.file_name = name

        self.capabilities = []
        self.processes = []
        self.type = type
        self.initscript = ""
        self.program = None
        self.in_tcp = [False, False, False, []]
        self.in_udp = [False, False, False, []]
        self.out_tcp = [False, False, False, []]
        self.out_udp = [False, False, False, []]
        self.use_resolve = False
        self.use_tmp = False
        self.use_uid = False
        self.use_syslog = False
        self.use_kerberos = False
        self.manage_krb5_rcache = False
        self.use_pam = False
        self.use_dbus = False
        self.use_audit = False
        self.use_etc = self.type not in [EUSER, NEWTYPE]
        self.use_localization = self.type not in [EUSER, NEWTYPE]
        self.use_fd = self.type not in [EUSER, NEWTYPE]
        self.use_terminal = False
        self.use_mail = False
        self.booleans = {}
        self.files = {}
        self.dirs = {}
        self.found_tcp_ports = []
        self.found_udp_ports = []
        self.need_tcp_type = False
        self.need_udp_type = False
        self.admin_domains = []
        self.existing_domains = []
        self.transition_domains = []
        self.transition_users = []
        self.roles = []

    def __isnetset(self, l):
        return l[ALL] or l[RESERVED] or l[UNRESERVED] or len(l[PORTS]) > 0

    def set_admin_domains(self, admin_domains):
        self.admin_domains = admin_domains

    def set_existing_domains(self, existing_domains):
        self.existing_domains = existing_domains

    def set_admin_roles(self, roles):
        self.roles = roles

    def set_transition_domains(self, transition_domains):
        self.transition_domains = transition_domains

    def set_transition_users(self, transition_users):
        self.transition_users = transition_users

    def use_in_udp(self):
        return self.__isnetset(self.in_udp)

    def use_out_udp(self):
        return self.__isnetset(self.out_udp)

    def use_udp(self):
        return self.use_in_udp() or self.use_out_udp()

    def use_in_tcp(self):
        return self.__isnetset(self.in_tcp)

    def use_out_tcp(self):
        return self.__isnetset(self.out_tcp)

    def use_tcp(self):
        return self.use_in_tcp() or self.use_out_tcp()

    def use_network(self):
        return self.use_tcp() or self.use_udp()

    def find_port(self, port, protocol="tcp"):
        for begin, end, p in self.ports.keys():
            if port >= begin and port <= end and protocol == p:
                return self.ports[begin, end, protocol]
        return None

    def set_program(self, program):
        if self.type not in APPLICATIONS:
            raise ValueError(_("User Role types can not be assigned executables."))

        self.program = program

    def set_init_script(self, initscript):
        if self.type != DAEMON:
            raise ValueError(_("Only Daemon apps can use an init script."))

        self.initscript = initscript

    def set_in_tcp(self, all, reserved, unreserved, ports):
        self.in_tcp = [all, reserved, unreserved, verify_ports(ports)]

    def set_in_udp(self, all, reserved, unreserved, ports):
        self.in_udp = [all, reserved, unreserved, verify_ports(ports)]

    def set_out_tcp(self, all, ports):
        self.out_tcp = [all, False, False, verify_ports(ports)]

    def set_out_udp(self, all, ports):
        self.out_udp = [all, False, False, verify_ports(ports)]

    def set_use_resolve(self, val):
        if type(val) is not bool:
            raise ValueError(_("use_resolve must be a boolean value "))

        self.use_resolve = val

    def set_use_syslog(self, val):
        if type(val) is not bool:
            raise ValueError(_("use_syslog must be a boolean value "))

        self.use_syslog = val

    def set_use_kerberos(self, val):
        if type(val) is not bool:
            raise ValueError(_("use_kerberos must be a boolean value "))

        self.use_kerberos = val

    def set_manage_krb5_rcache(self, val):
        if type(val) is not bool:
            raise ValueError(_("manage_krb5_rcache must be a boolean value "))

        self.manage_krb5_rcache = val

    def set_use_pam(self, val):
        self.use_pam = (val is True)

    def set_use_dbus(self, val):
        self.use_dbus = (val is True)

    def set_use_audit(self, val):
        self.use_audit = (val is True)

    def set_use_etc(self, val):
        self.use_etc = (val is True)

    def set_use_localization(self, val):
        self.use_localization = (val is True)

    def set_use_fd(self, val):
        self.use_fd = (val is True)

    def set_use_terminal(self, val):
        self.use_terminal = (val is True)

    def set_use_mail(self, val):
        self.use_mail = (val is True)

    def set_use_tmp(self, val):
        if self.type in USERS:
            raise ValueError(_("USER Types automatically get a tmp type"))

        if val:
            self.DEFAULT_DIRS["/tmp"][1].append("/tmp")
        else:
            self.DEFAULT_DIRS["/tmp"][1] = []

    def set_use_uid(self, val):
        self.use_uid = (val is True)

    def generate_uid_rules(self):
        if self.use_uid:
            return re.sub("TEMPLATETYPE", self.name, executable.te_uid_rules)
        else:
            return ""

    def generate_syslog_rules(self):
        if self.use_syslog:
            return re.sub("TEMPLATETYPE", self.name, executable.te_syslog_rules)
        else:
            return ""

    def generate_resolve_rules(self):
        if self.use_resolve:
            return re.sub("TEMPLATETYPE", self.name, executable.te_resolve_rules)
        else:
            return ""

    def generate_kerberos_rules(self):
        if self.use_kerberos:
            return re.sub("TEMPLATETYPE", self.name, executable.te_kerberos_rules)
        else:
            return ""

    def generate_manage_krb5_rcache_rules(self):
        if self.manage_krb5_rcache:
            return re.sub("TEMPLATETYPE", self.name, executable.te_manage_krb5_rcache_rules)
        else:
            return ""

    def generate_pam_rules(self):
        newte = ""
        if self.use_pam:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_pam_rules)
        return newte

    def generate_audit_rules(self):
        newte = ""
        if self.use_audit:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_audit_rules)
        return newte

    def generate_etc_rules(self):
        newte = ""
        if self.use_etc:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_etc_rules)
        return newte

    def generate_fd_rules(self):
        newte = ""
        if self.use_fd:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_fd_rules)
        return newte

    def generate_localization_rules(self):
        newte = ""
        if self.use_localization:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_localization_rules)
        return newte

    def generate_dbus_rules(self):
        newte = ""
        if self.type != DBUS and self.use_dbus:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_dbus_rules)
        return newte

    def generate_mail_rules(self):
        newte = ""
        if self.use_mail:
            newte = re.sub("TEMPLATETYPE", self.name, executable.te_mail_rules)
        return newte

    def generate_network_action(self, protocol, action, port_name):
        line = ""
        method = "corenet_%s_%s_%s" % (protocol, action, port_name)
        if method in sepolicy.get_methods():
            line = "%s(%s_t)\n" % (method, self.name)
        else:
            line = """
gen_require(`
    type %s_t;
')
allow %s_t %s_t:%s_socket name_%s;
""" % (port_name, self.name, port_name, protocol, action)
        return line

    def generate_network_types(self):
        for i in self.in_tcp[PORTS]:
            rec = self.find_port(int(i), "tcp")
            if rec is None:
                self.need_tcp_type = True
            else:
                port_name = rec[0][:-2]
                line = self.generate_network_action("tcp", "bind", port_name)
#                   line = "corenet_tcp_bind_%s(%s_t)\n" % (port_name, self.name)
                if line not in self.found_tcp_ports:
                    self.found_tcp_ports.append(line)

        for i in self.out_tcp[PORTS]:
            rec = self.find_port(int(i), "tcp")
            if rec is None:
                self.need_tcp_type = True
            else:
                port_name = rec[0][:-2]
                line = self.generate_network_action("tcp", "connect", port_name)
#                   line = "corenet_tcp_connect_%s(%s_t)\n" % (port_name, self.name)
                if line not in self.found_tcp_ports:
                    self.found_tcp_ports.append(line)

        for i in self.in_udp[PORTS]:
            rec = self.find_port(int(i), "udp")
            if rec is None:
                self.need_udp_type = True
            else:
                port_name = rec[0][:-2]
                line = self.generate_network_action("udp", "bind", port_name)
#                   line = "corenet_udp_bind_%s(%s_t)\n" % (port_name, self.name)
                if line not in self.found_udp_ports:
                    self.found_udp_ports.append(line)

        if self.need_udp_type is True or self.need_tcp_type is True:
            return re.sub("TEMPLATETYPE", self.name, network.te_types)
        return ""

    def __find_path(self, file):
        for d in self.DEFAULT_DIRS:
            if file.find(d) == 0:
                self.DEFAULT_DIRS[d][1].append(file)
                return self.DEFAULT_DIRS[d]
        self.DEFAULT_DIRS["rw"][1].append(file)
        return self.DEFAULT_DIRS["rw"]

    def add_capability(self, capability):
        if capability not in self.capabilities:
            self.capabilities.append(capability)

    def set_types(self, types):
        self.types = types

    def add_process(self, process):
        if process not in self.processes:
            self.processes.append(process)

    def add_boolean(self, name, description):
        self.booleans[name] = description

    def add_file(self, file):
        self.files[file] = self.__find_path(file)

    def add_dir(self, file):
        self.dirs[file] = self.__find_path(file)

    def generate_capabilities(self):
        newte = ""
        self.capabilities.sort()
        if len(self.capabilities) > 0:
            newte = "allow %s_t self:capability { %s };\n" % (self.name, " ".join(self.capabilities))
        return newte

    def generate_process(self):
        newte = ""
        self.processes.sort()
        if len(self.processes) > 0:
            newte = "allow %s_t self:process { %s };\n" % (self.name, " ".join(self.processes))
        return newte

    def generate_network_rules(self):
        newte = ""
        if self.use_network():
            newte = "\n"

            newte += re.sub("TEMPLATETYPE", self.name, network.te_network)

            if self.use_tcp():
                newte += "\n"
                newte += re.sub("TEMPLATETYPE", self.name, network.te_tcp)

                if self.use_in_tcp():
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_tcp)

                    if self.need_tcp_type and len(self.in_tcp[PORTS]) > 0:
                        newte += re.sub("TEMPLATETYPE", self.name, network.te_in_need_port_tcp)

                if self.need_tcp_type and len(self.out_tcp[PORTS]) > 0:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_out_need_port_tcp)

                if self.in_tcp[ALL]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_all_ports_tcp)
                if self.in_tcp[RESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_reserved_ports_tcp)
                if self.in_tcp[UNRESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_unreserved_ports_tcp)

                if self.out_tcp[ALL]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_out_all_ports_tcp)
                if self.out_tcp[RESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_out_reserved_ports_tcp)
                if self.out_tcp[UNRESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_out_unreserved_ports_tcp)

                for i in self.found_tcp_ports:
                    newte += i

            if self.use_udp():
                newte += "\n"
                newte += re.sub("TEMPLATETYPE", self.name, network.te_udp)

                if self.need_udp_type:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_need_port_udp)
                if self.use_in_udp():
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_udp)
                if self.in_udp[ALL]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_all_ports_udp)
                if self.in_udp[RESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_reserved_ports_udp)
                if self.in_udp[UNRESERVED]:
                    newte += re.sub("TEMPLATETYPE", self.name, network.te_in_unreserved_ports_udp)

                for i in self.found_udp_ports:
                    newte += i
        return newte

    def generate_transition_rules(self):
        newte = ""
        for app in self.transition_domains:
            tmp = re.sub("TEMPLATETYPE", self.name, user.te_transition_rules)
            newte += re.sub("APPLICATION", app, tmp)

        if self.type == USER:
            for u in self.transition_users:
                temp = re.sub("TEMPLATETYPE", self.name, executable.te_run_rules)
                newte += re.sub("USER", u.split("_u")[0], temp)

        return newte

    def generate_admin_rules(self):
        newte = ""
        if self.type == EUSER:
            for d in self.existing_domains:
                name = d.split("_t")[0]
                role = name + "_r"
                for app in self.admin_domains:
                    tmp = re.sub("TEMPLATETYPE", name, user.te_admin_domain_rules)
                    if role not in self.all_roles:
                        tmp = re.sub(role, "system_r", tmp)

                    newte += re.sub("APPLICATION", app, tmp)

            return newte

        if self.type == RUSER:
            newte += re.sub("TEMPLATETYPE", self.name, user.te_admin_rules)

            for app in self.admin_domains:
                tmp = re.sub("TEMPLATETYPE", self.name, user.te_admin_domain_rules)
                newte += re.sub("APPLICATION", app, tmp)

            for u in self.transition_users:
                role = u.split("_u")[0]

                if (role + "_r") in self.all_roles:
                    tmp = re.sub("TEMPLATETYPE", self.name, user.te_admin_trans_rules)
                    newte += re.sub("USER", role, tmp)

        return newte

    def generate_dbus_if(self):
        newif = ""
        if self.use_dbus:
            newif = re.sub("TEMPLATETYPE", self.name, executable.if_dbus_rules)
        return newif

    def generate_sandbox_if(self):
        newif = ""
        if self.type != SANDBOX:
            return newif
        newif = re.sub("TEMPLATETYPE", self.name, executable.if_sandbox_rules)
        return newif

    def generate_admin_if(self):
        newif = ""
        newtypes = ""
        if self.initscript != "":
            newtypes += re.sub("TEMPLATETYPE", self.name, executable.if_initscript_admin_types)
            newif += re.sub("TEMPLATETYPE", self.name, executable.if_initscript_admin)
        for d in self.DEFAULT_KEYS:
            if len(self.DEFAULT_DIRS[d][1]) > 0:
                newtypes += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].if_admin_types)
                newif += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].if_admin_rules)

        if newif != "":
            ret = re.sub("TEMPLATETYPE", self.name, executable.if_begin_admin)
            ret += newtypes

            ret += re.sub("TEMPLATETYPE", self.name, executable.if_middle_admin)
            ret += newif
            ret += re.sub("TEMPLATETYPE", self.name, executable.if_end_admin)
            return ret

        return ""

    def generate_cgi_types(self):
        return re.sub("TEMPLATETYPE", self.file_name, executable.te_cgi_types)

    def generate_sandbox_types(self):
        return re.sub("TEMPLATETYPE", self.file_name, executable.te_sandbox_types)

    def generate_userapp_types(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_userapp_types)

    def generate_inetd_types(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_inetd_types)

    def generate_dbusd_types(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_dbusd_types)

    def generate_min_login_user_types(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_min_login_user_types)

    def generate_login_user_types(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_login_user_types)

    def generate_admin_user_types(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_admin_user_types)

    def generate_existing_user_types(self):
        if len(self.existing_domains) == 0:
            raise ValueError(_("'%s' policy modules require existing domains") % poltype[self.type])
        newte = re.sub("TEMPLATETYPE", self.name, user.te_existing_user_types)
        newte += """gen_require(`"""

        for d in self.existing_domains:
            newte += """
        type %s;""" % d
            role = d.split("_t")[0] + "_r"
            if role in self.all_roles:
                newte += """
	role %s;""" % role
        newte += """
')
"""
        return newte

    def generate_x_login_user_types(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_x_login_user_types)

    def generate_root_user_types(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_root_user_types)

    def generate_new_types(self):
        newte = ""
        if len(self.types) == 0:
            raise ValueError(_("Type field required"))

        for t in self.types:
            for i in self.DEFAULT_EXT:
                if t.endswith(i):
                    print(t, t[:-len(i)])
                    newte += re.sub("TEMPLATETYPE", t[:-len(i)], self.DEFAULT_EXT[i].te_types)
                    break

        if NEWTYPE and newte == "":
            default_ext = []
            for i in self.DEFAULT_EXT:
                default_ext.append(i)
            raise ValueError(_("You need to define a new type which ends with: \n %s") % "\n ".join(default_ext))

        return newte

    def generate_new_rules(self):
        return ""

    def generate_daemon_types(self):
        newte = re.sub("TEMPLATETYPE", self.name, executable.te_daemon_types)
        if self.initscript != "":
            newte += re.sub("TEMPLATETYPE", self.name, executable.te_initscript_types)
        return newte

    def generate_tmp_types(self):
        if self.use_tmp:
            return re.sub("TEMPLATETYPE", self.name, tmp.te_types)
        else:
            return ""

    def generate_booleans(self):
        newte = ""
        for b in self.booleans:
            tmp = re.sub("BOOLEAN", b, boolean.te_boolean)
            newte += re.sub("DESCRIPTION", self.booleans[b], tmp)
        return newte

    def generate_boolean_rules(self):
        newte = ""
        for b in self.booleans:
            newte += re.sub("BOOLEAN", b, boolean.te_rules)
        return newte

    def generate_sandbox_te(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_sandbox_types)

    def generate_cgi_te(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_cgi_types)

    def generate_daemon_rules(self):
        newif = re.sub("TEMPLATETYPE", self.name, executable.te_daemon_rules)

        return newif

    def generate_new_type_if(self):
        newif = ""
        for t in self.types:
            for i in self.DEFAULT_EXT:
                if t.endswith(i):
                    reqtype = t[:-len(i)] + "_t"
                    newif += re.sub("TEMPLATETYPE", t[:-len(i)], self.DEFAULT_EXT[i].if_rules)
                    break
        return newif

    def generate_login_user_rules(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_login_user_rules)

    def generate_existing_user_rules(self):
        nerules = re.sub("TEMPLATETYPE", self.name, user.te_existing_user_rules)
        return nerules

    def generate_x_login_user_rules(self):
        return re.sub("TEMPLATETYPE", self.name, user.te_x_login_user_rules)

    def generate_root_user_rules(self):
        newte = re.sub("TEMPLATETYPE", self.name, user.te_root_user_rules)
        return newte

    def generate_userapp_rules(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_userapp_rules)

    def generate_inetd_rules(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_inetd_rules)

    def generate_dbusd_rules(self):
        return re.sub("TEMPLATETYPE", self.name, executable.te_dbusd_rules)

    def generate_tmp_rules(self):
        if self.use_tmp:
            return re.sub("TEMPLATETYPE", self.name, tmp.te_rules)
        else:
            return ""

    def generate_cgi_rules(self):
        newte = ""
        newte += re.sub("TEMPLATETYPE", self.name, executable.te_cgi_rules)
        return newte

    def generate_sandbox_rules(self):
        newte = ""
        newte += re.sub("TEMPLATETYPE", self.name, executable.te_sandbox_rules)
        return newte

    def generate_user_if(self):
        newif = ""
        if self.use_terminal or self.type == USER:
            newif = re.sub("TEMPLATETYPE", self.name, executable.if_user_program_rules)

        if self.type in (TUSER, XUSER, AUSER, LUSER):
            newif += re.sub("TEMPLATETYPE", self.name, executable.if_role_change_rules)
        return newif

    def generate_if(self):
        newif = ""
        newif += re.sub("TEMPLATETYPE", self.name, executable.if_heading_rules)
        if self.program:
            newif += re.sub("TEMPLATETYPE", self.name, executable.if_program_rules)
        if self.initscript != "":
            newif += re.sub("TEMPLATETYPE", self.name, executable.if_initscript_rules)

        for d in self.DEFAULT_KEYS:
            if len(self.DEFAULT_DIRS[d][1]) > 0:
                newif += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].if_rules)
                for i in self.DEFAULT_DIRS[d][1]:
                    if os.path.exists(i) and stat.S_ISSOCK(os.stat(i)[stat.ST_MODE]):
                        newif += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].if_stream_rules)
                        break
        newif += self.generate_user_if()
        newif += self.generate_dbus_if()
        newif += self.generate_admin_if()
        newif += self.generate_sandbox_if()
        newif += self.generate_new_type_if()
        newif += self.generate_new_rules()

        return newif

    def generate_default_types(self):
        return self.DEFAULT_TYPES[self.type][0]()

    def generate_default_rules(self):
        if self.DEFAULT_TYPES[self.type][1]:
            return self.DEFAULT_TYPES[self.type][1]()
        return ""

    def generate_roles_rules(self):
        newte = ""
        if self.type in (TUSER, XUSER, AUSER, LUSER):
            roles = ""
            if len(self.roles) > 0:
                newte += re.sub("TEMPLATETYPE", self.name, user.te_sudo_rules)
                newte += re.sub("TEMPLATETYPE", self.name, user.te_newrole_rules)
                for role in self.roles:
                    tmp = re.sub("TEMPLATETYPE", self.name, user.te_roles_rules)
                    newte += re.sub("ROLE", role, tmp)
        return newte

    def generate_te(self):
        newte = self.generate_default_types()
        for d in self.DEFAULT_KEYS:
            if len(self.DEFAULT_DIRS[d][1]) > 0:
                # CGI scripts already have a rw_t
                if self.type != CGI or d != "rw":
                    newte += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].te_types)

        if self.type != EUSER:
            newte += """
########################################
#
# %s local policy
#
""" % self.name
        newte += self.generate_capabilities()
        newte += self.generate_process()
        newte += self.generate_network_types()
        newte += self.generate_tmp_types()
        newte += self.generate_booleans()
        newte += self.generate_default_rules()
        newte += self.generate_boolean_rules()

        for d in self.DEFAULT_KEYS:
            if len(self.DEFAULT_DIRS[d][1]) > 0:
                if self.type == EUSER:
                    newte_tmp = ""
                    for domain in self.existing_domains:
                        newte_tmp += re.sub("TEMPLATETYPE_t", domain[:-2] + "_t", self.DEFAULT_DIRS[d][2].te_rules)
                        newte += re.sub("TEMPLATETYPE_rw_t", self.name + "_rw_t", newte_tmp)
                else:
                    newte += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].te_rules)
                for i in self.DEFAULT_DIRS[d][1]:
                    if os.path.exists(i) and stat.S_ISSOCK(os.stat(i)[stat.ST_MODE]):
                        if self.type == EUSER:
                            for domain in self.existing_domains:
                                newte += re.sub("TEMPLATETYPE", domain[:-2], self.DEFAULT_DIRS[d][2].te_stream_rules)

                        else:
                            newte += re.sub("TEMPLATETYPE", self.name, self.DEFAULT_DIRS[d][2].te_stream_rules)
                        break

        newte += self.generate_tmp_rules()
        newte += self.generate_network_rules()
        newte += self.generate_fd_rules()
        newte += self.generate_etc_rules()
        newte += self.generate_pam_rules()
        newte += self.generate_uid_rules()
        newte += self.generate_audit_rules()
        newte += self.generate_syslog_rules()
        newte += self.generate_localization_rules()
        newte += self.generate_resolve_rules()
        newte += self.generate_roles_rules()
        newte += self.generate_mail_rules()
        newte += self.generate_transition_rules()
        newte += self.generate_admin_rules()
        newte += self.generate_dbus_rules()
        newte += self.generate_kerberos_rules()
        newte += self.generate_manage_krb5_rcache_rules()

        return newte

    def generate_fc(self):
        newfc = ""
        fclist = []
        for i in self.files.keys():
            if os.path.exists(i) and stat.S_ISSOCK(os.stat(i)[stat.ST_MODE]):
                t1 = re.sub("TEMPLATETYPE", self.name, self.files[i][2].fc_sock_file)
            else:
                t1 = re.sub("TEMPLATETYPE", self.name, self.files[i][2].fc_file)
            t2 = re.sub("FILENAME", i, t1)
            fclist.append(re.sub("FILETYPE", self.files[i][0], t2))

        for i in self.dirs.keys():
            t1 = re.sub("TEMPLATETYPE", self.name, self.dirs[i][2].fc_dir)
            t2 = re.sub("FILENAME", i, t1)
            fclist.append(re.sub("FILETYPE", self.dirs[i][0], t2))

        if self.type in USERS + [SANDBOX]:
            if len(fclist) == 0:
                return executable.fc_user

        if self.type not in USERS + [SANDBOX, EUSER, NEWTYPE] and not self.program:
            raise ValueError(_("You must enter the executable path for your confined process"))

        if self.program:
            t1 = re.sub("EXECUTABLE", self.program, executable.fc_program)
            fclist.append(re.sub("TEMPLATETYPE", self.name, t1))

        if self.initscript != "":
            t1 = re.sub("EXECUTABLE", self.initscript, executable.fc_initscript)
            fclist.append(re.sub("TEMPLATETYPE", self.name, t1))

        fclist.sort()
        newfc = "\n".join(fclist)
        return newfc

    def generate_user_sh(self):
        newsh = ""
        if self.type not in (TUSER, XUSER, AUSER, LUSER, RUSER):
            return newsh

        roles = ""
        for role in self.roles:
            roles += " %s_r" % role
        if roles != "":
            roles += " system_r"
        tmp = re.sub("TEMPLATETYPE", self.name, script.users)
        newsh += re.sub("ROLES", roles, tmp)

        if self.type == RUSER or self.type == AUSER:
            for u in self.transition_users:
                tmp = re.sub("TEMPLATETYPE", self.name, script.admin_trans)
                newsh += re.sub("USER", u, tmp)

        if self.type == LUSER:
            newsh += re.sub("TEMPLATETYPE", self.name, script.min_login_user_default_context)
        else:
            newsh += re.sub("TEMPLATETYPE", self.name, script.x_login_user_default_context)

        return newsh

    def generate_sh(self):
        temp = re.sub("TEMPLATETYPE", self.file_name, script.compile)
        temp = re.sub("DOMAINTYPE", self.name, temp)
        if self.type == EUSER:
            newsh = re.sub("TEMPLATEFILE", "%s" % self.file_name, temp)
        else:
            newsh = re.sub("TEMPLATEFILE", self.file_name, temp)
            newsh += re.sub("DOMAINTYPE", self.name, script.manpage)

        if self.program:
            newsh += re.sub("FILENAME", self.program, script.restorecon)
        if self.initscript != "":
            newsh += re.sub("FILENAME", self.initscript, script.restorecon)

        for i in self.files.keys():
            newsh += re.sub("FILENAME", i, script.restorecon)

        for i in self.dirs.keys():
            newsh += re.sub("FILENAME", i, script.restorecon)

        for i in self.in_tcp[PORTS] + self.out_tcp[PORTS]:
            if self.find_port(i, "tcp") is None:
                t1 = re.sub("PORTNUM", "%d" % i, script.tcp_ports)
                newsh += re.sub("TEMPLATETYPE", self.name, t1)

        for i in self.in_udp[PORTS]:
            if self.find_port(i, "udp") is None:
                t1 = re.sub("PORTNUM", "%d" % i, script.udp_ports)
                newsh += re.sub("TEMPLATETYPE", self.name, t1)

        newsh += self.generate_user_sh()
        newsh += re.sub("TEMPLATEFILE", self.file_name, script.rpm)

        return newsh

    def generate_spec(self):
        newspec = ""

        selinux_policynvr = get_rpm_nvr_list("selinux-policy")

        if selinux_policynvr is None:
            selinux_policyver = "0.0.0"
        else:
            selinux_policyver = selinux_policynvr[1]

        newspec += spec.header_comment_section
        if self.type in APPLICATIONS:
            newspec += spec.define_relabel_files_begin
            if self.program:
                newspec += re.sub("FILENAME", self.program, spec.define_relabel_files_end)
            if self.initscript != "":
                newspec += re.sub("FILENAME", self.initscript, spec.define_relabel_files_end)
            for i in self.files.keys():
                newspec += re.sub("FILENAME", i, spec.define_relabel_files_end)
            for i in self.dirs.keys():
                newspec += re.sub("FILENAME", i, spec.define_relabel_files_end)

        newspec += re.sub("VERSION", selinux_policyver, spec.base_section)
        newspec = re.sub("MODULENAME", self.file_name, newspec)
        newspec = re.sub("DOMAINNAME", self.name, newspec)
        if len(self.rpms) > 0:
            newspec += "Requires(post): %s\n" % ", ".join(self.rpms)
        newspec += re.sub("MODULENAME", self.file_name, spec.mid_section)
        newspec = re.sub("DOMAINNAME", self.name, newspec)
        newspec = re.sub("TODAYSDATE", time.strftime("%a %b %e %Y"), newspec)

        if self.type not in APPLICATIONS:
            newspec = re.sub("%relabel_files", "", newspec)

        # Remove man pages from EUSER spec file
        if self.type == EUSER:
            newspec = re.sub(".*%s_selinux.8.*" % self.name, "", newspec)
        # Remove user context file from non users spec file
        if self.type not in (TUSER, XUSER, AUSER, LUSER, RUSER):
            newspec = re.sub(".*%s_u.*" % self.name, "", newspec)
        return newspec

    def write_spec(self, out_dir):
        specfile = "%s/%s_selinux.spec" % (out_dir, self.file_name)
        fd = open(specfile, "w")
        fd.write(self.generate_spec())
        fd.close()

        return specfile

    def write_te(self, out_dir):
        tefile = "%s/%s.te" % (out_dir, self.file_name)
        fd = open(tefile, "w")
        fd.write(self.generate_te())
        fd.close()
        return tefile

    def write_sh(self, out_dir):
        shfile = "%s/%s.sh" % (out_dir, self.file_name)
        fd = open(shfile, "w")
        fd.write(self.generate_sh())
        fd.close()
        os.chmod(shfile, 0o750)
        return shfile

    def write_if(self, out_dir):
        iffile = "%s/%s.if" % (out_dir, self.file_name)
        fd = open(iffile, "w")
        fd.write(self.generate_if())
        fd.close()
        return iffile

    def write_fc(self, out_dir):
        fcfile = "%s/%s.fc" % (out_dir, self.file_name)
        fd = open(fcfile, "w")
        fd.write(self.generate_fc())
        fd.close()
        return fcfile

    def __extract_rpms(self):
        import yum
        yb = yum.YumBase()
        yb.setCacheDir()

        for pkg in yb.rpmdb.searchProvides(self.program):
            self.rpms.append(pkg.name)
            for fname in pkg.dirlist + pkg.filelist + pkg.ghostlist:
                for b in self.DEFAULT_DIRS:
                    if b == "/etc":
                        continue
                    if fname.startswith(b):
                        if os.path.isfile(fname):
                            self.add_file(fname)
                        else:
                            self.add_dir(fname)

            for bpkg in yb.rpmdb.searchNames([pkg.base_package_name]):
                for fname in bpkg.dirlist + bpkg.filelist + bpkg.ghostlist:
                    for b in self.DEFAULT_DIRS:
                        if b == "/etc":
                            continue
                        if fname.startswith(b):
                            if os.path.isfile(fname):
                                self.add_file(fname)
                            else:
                                self.add_dir(fname)

        # some packages have own systemd subpackage
        # tor-systemd for example
        binary_name = self.program.split("/")[-1]
        for bpkg in yb.rpmdb.searchNames(["%s-systemd" % binary_name]):
            for fname in bpkg.filelist + bpkg.ghostlist + bpkg.dirlist:
                for b in self.DEFAULT_DIRS:
                    if b == "/etc":
                        continue
                    if fname.startswith(b):
                        if os.path.isfile(fname):
                            self.add_file(fname)
                        else:
                            self.add_dir(fname)

    def gen_writeable(self):
        try:
            self.__extract_rpms()
        except ImportError:
            pass

        if os.path.isfile("/var/run/%s.pid" % self.name):
            self.add_file("/var/run/%s.pid" % self.name)

        if os.path.isdir("/var/run/%s" % self.name):
            self.add_dir("/var/run/%s" % self.name)

        if os.path.isdir("/var/log/%s" % self.name):
            self.add_dir("/var/log/%s" % self.name)

        if os.path.isfile("/var/log/%s.log" % self.name):
            self.add_file("/var/log/%s.log" % self.name)

        if os.path.isdir("/var/lib/%s" % self.name):
            self.add_dir("/var/lib/%s" % self.name)

        if os.path.isfile("/etc/rc.d/init.d/%s" % self.name):
            self.set_init_script(r"/etc/rc\.d/init\.d/%s" % self.name)

        # we don't want to have subdir in the .fc policy file
        # if we already specify labeling for parent dir
        temp_basepath = []
        for p in self.DEFAULT_DIRS.keys():
            temp_dirs = []
            try:
                temp_basepath = self.DEFAULT_DIRS[p][1][0] + "/"
            except IndexError:
                continue

            for i in self.DEFAULT_DIRS[p][1]:
                if i.startswith(temp_basepath):
                    temp_dirs.append(i)
                else:
                    continue

            if len(temp_dirs) != 0:
                for i in temp_dirs:
                    if i in self.dirs.keys():
                        del(self.dirs[i])
                    elif i in self.files.keys():
                        del(self.files[i])
                    else:
                        continue

                self.DEFAULT_DIRS[p][1] = list(set(self.DEFAULT_DIRS[p][1]) - set(temp_dirs))

    def gen_symbols(self):
        if self.type not in APPLICATIONS:
            return
        if not os.path.exists(self.program):
            sys.stderr.write("""
***************************************
Warning %s does not exist
***************************************

""" % self.program)
            return
        fd = os.popen("nm -D %s | grep U" % self.program)
        for s in fd.read().split():
            for b in self.symbols:
                if s.startswith(b):
                    exec("self.%s" % self.symbols[b])
        fd.close()

    def generate(self, out_dir=os.getcwd()):
        out = "Created the following files:\n"
        out += "%s # %s\n" % (self.write_te(out_dir), _("Type Enforcement file"))
        out += "%s # %s\n" % (self.write_if(out_dir), _("Interface file"))
        out += "%s # %s\n" % (self.write_fc(out_dir), _("File Contexts file"))
        if self.type != NEWTYPE:
            out += "%s # %s\n" % (self.write_spec(out_dir), _("Spec file"))
            out += "%s # %s\n" % (self.write_sh(out_dir), _("Setup Script"))
        return out
