# Copyright (C) 2005-2013 Red Hat
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

import pwd
import grp
import selinux
import os
import re
import sys
import stat
import socket
from semanage import *
PROGNAME = "selinux-python"
import sepolicy
from setools.policyrep import SELinuxPolicy
from setools.typequery import TypeQuery
import ipaddress

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

import syslog

file_types = {}
file_types[""] = SEMANAGE_FCONTEXT_ALL
file_types["all files"] = SEMANAGE_FCONTEXT_ALL
file_types["a"] = SEMANAGE_FCONTEXT_ALL
file_types["regular file"] = SEMANAGE_FCONTEXT_REG
file_types["--"] = SEMANAGE_FCONTEXT_REG
file_types["f"] = SEMANAGE_FCONTEXT_REG
file_types["-d"] = SEMANAGE_FCONTEXT_DIR
file_types["directory"] = SEMANAGE_FCONTEXT_DIR
file_types["d"] = SEMANAGE_FCONTEXT_DIR
file_types["-c"] = SEMANAGE_FCONTEXT_CHAR
file_types["character device"] = SEMANAGE_FCONTEXT_CHAR
file_types["c"] = SEMANAGE_FCONTEXT_CHAR
file_types["-b"] = SEMANAGE_FCONTEXT_BLOCK
file_types["block device"] = SEMANAGE_FCONTEXT_BLOCK
file_types["b"] = SEMANAGE_FCONTEXT_BLOCK
file_types["-s"] = SEMANAGE_FCONTEXT_SOCK
file_types["socket"] = SEMANAGE_FCONTEXT_SOCK
file_types["s"] = SEMANAGE_FCONTEXT_SOCK
file_types["-l"] = SEMANAGE_FCONTEXT_LINK
file_types["l"] = SEMANAGE_FCONTEXT_LINK
file_types["symbolic link"] = SEMANAGE_FCONTEXT_LINK
file_types["p"] = SEMANAGE_FCONTEXT_PIPE
file_types["-p"] = SEMANAGE_FCONTEXT_PIPE
file_types["named pipe"] = SEMANAGE_FCONTEXT_PIPE

file_type_str_to_option = {"all files": "a",
                           "regular file": "f",
                           "directory": "d",
                           "character device": "c",
                           "block device": "b",
                           "socket": "s",
                           "symbolic link": "l",
                           "named pipe": "p"}

ftype_to_audit = {"": "any",
                  "a" : "any",
                  "b": "block",
                  "c": "char",
                  "d": "dir",
                  "f": "file",
                  "l": "symlink",
                  "p": "pipe",
                  "s": "socket"}

try:
    import audit
    #test if audit module is enabled
    audit.audit_close(audit.audit_open())

    class logger:

        def __init__(self):
            self.audit_fd = audit.audit_open()
            self.log_list = []
            self.log_change_list = []

        def log(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):

            sep = "-"
            if sename != oldsename:
                msg += sep + "sename"
                sep = ","
            if serole != oldserole:
                msg += sep + "role"
                sep = ","
            if serange != oldserange:
                msg += sep + "range"
                sep = ","

            self.log_list.append([self.audit_fd, audit.AUDIT_ROLE_ASSIGN, sys.argv[0], str(msg), name, 0, sename, serole, serange, oldsename, oldserole, oldserange, "", "", ""])

        def log_remove(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):
            self.log_list.append([self.audit_fd, audit.AUDIT_ROLE_REMOVE, sys.argv[0], str(msg), name, 0, sename, serole, serange, oldsename, oldserole, oldserange, "", "", ""])

        def log_change(self, msg):
            self.log_change_list.append([self.audit_fd, audit.AUDIT_USER_MAC_CONFIG_CHANGE, str(msg), "semanage", "", "", ""])

        def commit(self, success):
            for l in self.log_list:
                audit.audit_log_semanage_message(*(l + [success]))
            for l in self.log_change_list:
                audit.audit_log_user_comm_message(*(l + [success]))

            self.log_list = []
            self.log_change_list = []
except (OSError, ImportError):
    class logger:

        def __init__(self):
            self.log_list = []

        def log(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):
            message = " %s name=%s" % (msg, name)
            if sename != "":
                message += " sename=" + sename
            if oldsename != "":
                message += " oldsename=" + oldsename
            if serole != "":
                message += " role=" + serole
            if oldserole != "":
                message += " old_role=" + oldserole
            if serange != "" and serange is not None:
                message += " MLSRange=" + serange
            if oldserange != "" and oldserange is not None:
                message += " old_MLSRange=" + oldserange
            self.log_list.append(message)

        def log_remove(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):
            self.log(msg, name, sename, serole, serange, oldsename, oldserole, oldserange)

        def log_change(self, msg):
            self.log_list.append(" %s" % msg)

        def commit(self, success):
            if success == 1:
                message = "Successful: "
            else:
                message = "Failed: "
            for l in self.log_list:
                syslog.syslog(syslog.LOG_INFO, message + l)


class nulllogger:

    def log(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):
        pass

    def log_remove(self, msg, name="", sename="", serole="", serange="", oldsename="", oldserole="", oldserange=""):
        pass

    def log_change(self, msg):
        pass

    def commit(self, success):
        pass


def validate_level(raw):
    sensitivity = "s[0-9]*"
    category = "c[0-9]*"
    cat_range = category + r"(\." + category + ")?"
    categories = cat_range + r"(\," + cat_range + ")*"
    reg = sensitivity + "(-" + sensitivity + ")?" + "(:" + categories + ")?"
    return re.search("^" + reg + "$", raw)


def translate(raw, prepend=1):
    filler = "a:b:c:"
    if prepend == 1:
        context = "%s%s" % (filler, raw)
    else:
        context = raw
    (rc, trans) = selinux.selinux_raw_to_trans_context(context)
    if rc != 0:
        return raw
    if prepend:
        trans = trans[len(filler):]
    if trans == "":
        return raw
    else:
        return trans


def untranslate(trans, prepend=1):
    filler = "a:b:c:"
    if prepend == 1:
        context = "%s%s" % (filler, trans)
    else:
        context = trans

    (rc, raw) = selinux.selinux_trans_to_raw_context(context)
    if rc != 0:
        return trans
    if prepend:
        raw = raw[len(filler):]
    if raw == "":
        return trans
    else:
        return raw


class semanageRecords:
    transaction = False
    handle = None
    store = None
    args = None

    def __init__(self, args = None):
        if args:
            # legacy code - args was store originally
            if isinstance(args, str):
                self.store = args
            else:
                self.args = args
        self.noreload = getattr(args, "noreload", False)
        if not self.store:
            self.store = getattr(args, "store", "")

        self.sh = self.get_handle(self.store)

        rc, localstore = selinux.selinux_getpolicytype()
        if self.store == "" or self.store == localstore:
            self.mylog = logger()
        else:
            sepolicy.load_store_policy(self.store)
            selinux.selinux_set_policy_root("%s%s" % (selinux.selinux_path(), self.store))
            self.mylog = nulllogger()

    def set_reload(self, load):
        self.noreload = not load

    def get_handle(self, store):
        global is_mls_enabled

        if semanageRecords.handle:
            return semanageRecords.handle

        handle = semanage_handle_create()
        if not handle:
            raise ValueError(_("Could not create semanage handle"))

        if not semanageRecords.transaction and store != "":
            semanage_select_store(handle, store, SEMANAGE_CON_DIRECT)
            semanageRecords.store = store

        if not semanage_is_managed(handle):
            semanage_handle_destroy(handle)
            raise ValueError(_("SELinux policy is not managed or store cannot be accessed."))

        rc = semanage_access_check(handle)
        if rc < SEMANAGE_CAN_READ:
            semanage_handle_destroy(handle)
            raise ValueError(_("Cannot read policy store."))

        rc = semanage_connect(handle)
        if rc < 0:
            semanage_handle_destroy(handle)
            raise ValueError(_("Could not establish semanage connection"))

        is_mls_enabled = semanage_mls_enabled(handle)
        if is_mls_enabled < 0:
            semanage_handle_destroy(handle)
            raise ValueError(_("Could not test MLS enabled status"))

        semanageRecords.handle = handle
        return semanageRecords.handle

    def deleteall(self):
        raise ValueError(_("Not yet implemented"))

    def start(self):
        if semanageRecords.transaction:
            raise ValueError(_("Semanage transaction already in progress"))
        self.begin()
        semanageRecords.transaction = True

    def begin(self):
        if semanageRecords.transaction:
            return
        rc = semanage_begin_transaction(self.sh)
        if rc < 0:
            raise ValueError(_("Could not start semanage transaction"))

    def customized(self):
        raise ValueError(_("Not yet implemented"))

    def commit(self):
        if semanageRecords.transaction:
            return

        if self.noreload:
            semanage_set_reload(self.sh, 0)
        rc = semanage_commit(self.sh)
        if rc < 0:
            self.mylog.commit(0)
            raise ValueError(_("Could not commit semanage transaction"))
        self.mylog.commit(1)

    def finish(self):
        if not semanageRecords.transaction:
            raise ValueError(_("Semanage transaction not in progress"))
        semanageRecords.transaction = False
        self.commit()


class moduleRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)

    def get_all(self):
        l = []
        (rc, mlist, number) = semanage_module_list_all(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list SELinux modules"))

        for i in range(number):
            mod = semanage_module_list_nth(mlist, i)

            rc, name = semanage_module_info_get_name(self.sh, mod)
            if rc < 0:
                raise ValueError(_("Could not get module name"))

            rc, enabled = semanage_module_info_get_enabled(self.sh, mod)
            if rc < 0:
                raise ValueError(_("Could not get module enabled"))

            rc, priority = semanage_module_info_get_priority(self.sh, mod)
            if rc < 0:
                raise ValueError(_("Could not get module priority"))

            rc, lang_ext = semanage_module_info_get_lang_ext(self.sh, mod)
            if rc < 0:
                raise ValueError(_("Could not get module lang_ext"))

            l.append((name, enabled, priority, lang_ext))

        # sort the list so they are in name order, but with higher priorities coming first
        l.sort(key=lambda t: t[3], reverse=True)
        l.sort(key=lambda t: t[0])
        return l

    def customized(self):
        all = self.get_all()
        if len(all) == 0:
            return []
        return ["-d %s" % x[0] for x in [t for t in all if t[1] == 0]]

    def list(self, heading=1, locallist=0):
        all = self.get_all()
        if len(all) == 0:
            return

        if heading:
            print("\n%-25s %-9s %s\n" % (_("Module Name"), _("Priority"), _("Language")))
        for t in all:
            if t[1] == 0:
                disabled = _("Disabled")
            else:
                if locallist:
                    continue
                disabled = ""
            print("%-25s %-9s %-5s %s" % (t[0], t[2], t[3], disabled))

    def add(self, file, priority):
        if not os.path.exists(file):
            raise ValueError(_("Module does not exist: %s ") % file)

        rc = semanage_set_default_priority(self.sh, priority)
        if rc < 0:
            raise ValueError(_("Invalid priority %d (needs to be between 1 and 999)") % priority)

        rc = semanage_module_install_file(self.sh, file)
        if rc >= 0:
            self.commit()

    def set_enabled(self, module, enable):
        for m in module.split():
            rc, key = semanage_module_key_create(self.sh)
            if rc < 0:
                raise ValueError(_("Could not create module key"))

            rc = semanage_module_key_set_name(self.sh, key, m)
            if rc < 0:
                raise ValueError(_("Could not set module key name"))

            rc = semanage_module_set_enabled(self.sh, key, enable)
            if rc < 0:
                if enable:
                    raise ValueError(_("Could not enable module %s") % m)
                else:
                    raise ValueError(_("Could not disable module %s") % m)
        self.commit()

    def delete(self, module, priority):
        rc = semanage_set_default_priority(self.sh, priority)
        if rc < 0:
            raise ValueError(_("Invalid priority %d (needs to be between 1 and 999)") % priority)

        for m in module.split():
            rc = semanage_module_remove(self.sh, m)
            if rc < 0 and rc != -2:
                raise ValueError(_("Could not remove module %s (remove failed)") % m)

        self.commit()

    def deleteall(self):
        l = [x[0] for x in [t for t in self.get_all() if t[1] == 0]]
        for m in l:
            self.set_enabled(m, True)


class dontauditClass(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)

    def toggle(self, dontaudit):
        if dontaudit not in ["on", "off"]:
            raise ValueError(_("dontaudit requires either 'on' or 'off'"))
        self.begin()
        semanage_set_disable_dontaudit(self.sh, dontaudit == "off")
        self.commit()


class permissiveRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)

    def get_all(self):
        l = []
        (rc, mlist, number) = semanage_module_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list SELinux modules"))

        for i in range(number):
            mod = semanage_module_list_nth(mlist, i)
            name = semanage_module_get_name(mod)
            if name and name.startswith("permissive_"):
                l.append(name.split("permissive_")[1])
        return l

    def customized(self):
        return ["-a %s" % x for x in sorted(self.get_all())]

    def list(self, heading=1, locallist=0):
        all = [y["name"] for y in [x for x in sepolicy.info(sepolicy.TYPE) if x["permissive"]]]
        if len(all) == 0:
            return

        if heading:
            print("\n%-25s\n" % (_("Builtin Permissive Types")))
        customized = self.get_all()
        for t in all:
            if t not in customized:
                print(t)

        if len(customized) == 0:
            return

        if heading:
            print("\n%-25s\n" % (_("Customized Permissive Types")))
        for t in customized:
            print(t)

    def add(self, type):
        name = "permissive_%s" % type
        modtxt = "(typepermissive %s)" % type

        rc = semanage_module_install(self.sh, modtxt, len(modtxt), name, "cil")
        if rc >= 0:
            self.commit()

        if rc < 0:
            raise ValueError(_("Could not set permissive domain %s (module installation failed)") % name)

    def delete(self, name):
        for n in name.split():
            rc = semanage_module_remove(self.sh, "permissive_%s" % n)
            if rc < 0:
                raise ValueError(_("Could not remove permissive domain %s (remove failed)") % name)

        self.commit()

    def deleteall(self):
        l = self.get_all()
        if len(l) > 0:
            all = " ".join(l)
            self.delete(all)


class loginRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        self.oldsename = None
        self.oldserange = None
        self.sename = None
        self.serange = None

    def __add(self, name, sename, serange):
        rec, self.oldsename, self.oldserange = selinux.getseuserbyname(name)
        if sename == "":
            sename = "user_u"

        userrec = seluserRecords(self.args)
        range, (rc, oldserole) = userrec.get(self.oldsename)
        range, (rc, serole) = userrec.get(sename)

        if is_mls_enabled == 1:
            if serange != "":
                serange = untranslate(serange)
            else:
                serange = range

        (rc, k) = semanage_seuser_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        if name[0] == '%':
            try:
                grp.getgrnam(name[1:])
            except:
                raise ValueError(_("Linux Group %s does not exist") % name[1:])
        else:
            try:
                pwd.getpwnam(name)
            except:
                raise ValueError(_("Linux User %s does not exist") % name)

        (rc, u) = semanage_seuser_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create login mapping for %s") % name)

        rc = semanage_seuser_set_name(self.sh, u, name)
        if rc < 0:
            raise ValueError(_("Could not set name for %s") % name)

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_seuser_set_mlsrange(self.sh, u, serange)
            if rc < 0:
                raise ValueError(_("Could not set MLS range for %s") % name)

        rc = semanage_seuser_set_sename(self.sh, u, sename)
        if rc < 0:
            raise ValueError(_("Could not set SELinux user for %s") % name)

        rc = semanage_seuser_modify_local(self.sh, k, u)
        if rc < 0:
            raise ValueError(_("Could not add login mapping for %s") % name)

        semanage_seuser_key_free(k)
        semanage_seuser_free(u)

    def add(self, name, sename, serange):
        try:
            self.begin()
            # Add a new mapping, or modify an existing one
            if self.__exists(name):
                print(_("Login mapping for %s is already defined, modifying instead") % name)
                self.__modify(name, sename, serange)
            else:
                self.__add(name, sename, serange)
            self.commit()
        except ValueError as error:
            raise error

    # check if login mapping for given user exists
    def __exists(self, name):
        (rc, k) = semanage_seuser_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_seuser_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if login mapping for %s is defined") % name)
        semanage_seuser_key_free(k)

        return exists

    def __modify(self, name, sename="", serange=""):
        rec, self.oldsename, self.oldserange = selinux.getseuserbyname(name)
        if sename == "" and serange == "":
            raise ValueError(_("Requires seuser or serange"))

        userrec = seluserRecords(self.args)
        range, (rc, oldserole) = userrec.get(self.oldsename)

        if sename != "":
            range, (rc, serole) = userrec.get(sename)
        else:
            serole = oldserole

        if serange != "":
            self.serange = serange
        else:
            self.serange = range

        (rc, k) = semanage_seuser_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_seuser_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if login mapping for %s is defined") % name)
        if not exists:
            raise ValueError(_("Login mapping for %s is not defined") % name)

        (rc, u) = semanage_seuser_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query seuser for %s") % name)

        self.oldserange = semanage_seuser_get_mlsrange(u)
        self.oldsename = semanage_seuser_get_sename(u)
        if (is_mls_enabled == 1) and (serange != ""):
            semanage_seuser_set_mlsrange(self.sh, u, untranslate(serange))

        if sename != "":
            semanage_seuser_set_sename(self.sh, u, sename)
            self.sename = sename
        else:
            self.sename = self.oldsename

        rc = semanage_seuser_modify_local(self.sh, k, u)
        if rc < 0:
            raise ValueError(_("Could not modify login mapping for %s") % name)

        semanage_seuser_key_free(k)
        semanage_seuser_free(u)

    def modify(self, name, sename="", serange=""):
        try:
            self.begin()
            self.__modify(name, sename, serange)
            self.commit()
        except ValueError as error:
            raise error

    def __delete(self, name):
        rec, self.oldsename, self.oldserange = selinux.getseuserbyname(name)
        userrec = seluserRecords(self.args)
        range, (rc, oldserole) = userrec.get(self.oldsename)

        (rc, k) = semanage_seuser_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_seuser_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if login mapping for %s is defined") % name)
        if not exists:
            raise ValueError(_("Login mapping for %s is not defined") % name)

        (rc, exists) = semanage_seuser_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if login mapping for %s is defined") % name)
        if not exists:
            raise ValueError(_("Login mapping for %s is defined in policy, cannot be deleted") % name)

        rc = semanage_seuser_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete login mapping for %s") % name)

        semanage_seuser_key_free(k)

        rec, self.sename, self.serange = selinux.getseuserbyname("__default__")
        range, (rc, serole) = userrec.get(self.sename)

    def delete(self, name):
        try:
            self.begin()
            self.__delete(name)
            self.commit()

        except ValueError as error:
            raise error

    def deleteall(self):
        (rc, ulist) = semanage_seuser_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list login mappings"))

        try:
            self.begin()
            for u in ulist:
                self.__delete(semanage_seuser_get_name(u))
            self.commit()
        except ValueError as error:
            raise error

    def get_all_logins(self):
        ddict = {}
        self.logins_path = selinux.selinux_policy_root() + "/logins"
        for path, dirs, files in os.walk(self.logins_path):
            if path == self.logins_path:
                for name in files:
                    try:
                        fd = open(path + "/" + name)
                        rec = fd.read().rstrip().split(":")
                        fd.close()
                        ddict[name] = (rec[1], rec[2], rec[0])
                    except IndexError:
                        pass
        return ddict

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.ulist) = semanage_seuser_list_local(self.sh)
        else:
            (rc, self.ulist) = semanage_seuser_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list login mappings"))

        for u in self.ulist:
            name = semanage_seuser_get_name(u)
            ddict[name] = (semanage_seuser_get_sename(u), semanage_seuser_get_mlsrange(u), "*")
        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            if ddict[k][1]:
                l.append("-a -s %s -r '%s' %s" % (ddict[k][0], ddict[k][1], k))
            else:
                l.append("-a -s %s %s" % (ddict[k][0], k))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all(locallist)
        ldict = self.get_all_logins()
        lkeys = sorted(ldict.keys())
        keys = sorted(ddict.keys())
        if len(keys) == 0 and len(lkeys) == 0:
            return

        if is_mls_enabled == 1:
            if heading:
                print("\n%-20s %-20s %-20s %s\n" % (_("Login Name"), _("SELinux User"), _("MLS/MCS Range"), _("Service")))
            for k in keys:
                u = ddict[k]
                print("%-20s %-20s %-20s %s" % (k, u[0], translate(u[1]), u[2]))
            if len(lkeys):
                print("\nLocal customization in %s" % self.logins_path)

            for k in lkeys:
                u = ldict[k]
                print("%-20s %-20s %-20s %s" % (k, u[0], translate(u[1]), u[2]))
        else:
            if heading:
                print("\n%-25s %-25s\n" % (_("Login Name"), _("SELinux User")))
            for k in keys:
                print("%-25s %-25s" % (k, ddict[k][0]))


class seluserRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)

    def get(self, name):
        (rc, k) = semanage_user_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)
        (rc, exists) = semanage_user_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if SELinux user %s is defined") % name)
        (rc, u) = semanage_user_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query user for %s") % name)
        serange = semanage_user_get_mlsrange(u)
        serole = semanage_user_get_roles(self.sh, u)
        semanage_user_key_free(k)
        semanage_user_free(u)
        return serange, serole

    def __add(self, name, roles, selevel, serange, prefix):
        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

            if selevel == "":
                selevel = "s0"
            else:
                selevel = untranslate(selevel)

        if len(roles) < 1:
            raise ValueError(_("You must add at least one role for %s") % name)

        (rc, k) = semanage_user_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, u) = semanage_user_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create SELinux user for %s") % name)

        rc = semanage_user_set_name(self.sh, u, name)
        if rc < 0:
            raise ValueError(_("Could not set name for %s") % name)

        for r in roles:
            rc = semanage_user_add_role(self.sh, u, r)
            if rc < 0:
                raise ValueError(_("Could not add role {role} for {name}").format(role=r, name=name))

        if is_mls_enabled == 1:
            rc = semanage_user_set_mlsrange(self.sh, u, serange)
            if rc < 0:
                raise ValueError(_("Could not set MLS range for %s") % name)

            rc = semanage_user_set_mlslevel(self.sh, u, selevel)
            if rc < 0:
                raise ValueError(_("Could not set MLS level for %s") % name)
        rc = semanage_user_set_prefix(self.sh, u, prefix)
        if rc < 0:
            raise ValueError(_("Could not add prefix {prefix} for {role}").format(role=r, prefix=prefix))
        (rc, key) = semanage_user_key_extract(self.sh, u)
        if rc < 0:
            raise ValueError(_("Could not extract key for %s") % name)

        rc = semanage_user_modify_local(self.sh, k, u)
        if rc < 0:
            raise ValueError(_("Could not add SELinux user %s") % name)

        semanage_user_key_free(k)
        semanage_user_free(u)
        self.mylog.log("seuser", sename=name, serole=",".join(roles), serange=serange)

    def add(self, name, roles, selevel, serange, prefix):
        try:
            self.begin()
            if self.__exists(name):
                print(_("SELinux user %s is already defined, modifying instead") % name)
                self.__modify(name, roles, selevel, serange, prefix)
            else:
                self.__add(name, roles, selevel, serange, prefix)
            self.commit()
        except ValueError as error:
            self.mylog.commit(0)
            raise error

    def __exists(self, name):
        (rc, k) = semanage_user_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_user_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if SELinux user %s is defined") % name)
        semanage_user_key_free(k)

        return exists

    def __modify(self, name, roles=[], selevel="", serange="", prefix=""):
        oldserole = ""
        oldserange = ""
        newroles = " ".join(roles)
        if prefix == "" and len(roles) == 0 and serange == "" and selevel == "":
            if is_mls_enabled == 1:
                raise ValueError(_("Requires prefix, roles, level or range"))
            else:
                raise ValueError(_("Requires prefix or roles"))

        (rc, k) = semanage_user_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_user_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if SELinux user %s is defined") % name)
        if not exists:
            raise ValueError(_("SELinux user %s is not defined") % name)

        (rc, u) = semanage_user_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query user for %s") % name)

        oldserange = semanage_user_get_mlsrange(u)
        (rc, rlist) = semanage_user_get_roles(self.sh, u)
        if rc >= 0:
            oldserole = " ".join(rlist)

        if (is_mls_enabled == 1) and (serange != ""):
            semanage_user_set_mlsrange(self.sh, u, untranslate(serange))
        if (is_mls_enabled == 1) and (selevel != ""):
            semanage_user_set_mlslevel(self.sh, u, untranslate(selevel))

        if prefix != "":
            semanage_user_set_prefix(self.sh, u, prefix)

        if len(roles) != 0:
            for r in rlist:
                if r not in roles:
                    semanage_user_del_role(u, r)
            for r in roles:
                if r not in rlist:
                    semanage_user_add_role(self.sh, u, r)

        rc = semanage_user_modify_local(self.sh, k, u)
        if rc < 0:
            raise ValueError(_("Could not modify SELinux user %s") % name)

        semanage_user_key_free(k)
        semanage_user_free(u)

        role = ",".join(newroles.split())
        oldserole = ",".join(oldserole.split())
        self.mylog.log("seuser", sename=name, oldsename=name, serole=role, serange=serange, oldserole=oldserole, oldserange=oldserange)

    def modify(self, name, roles=[], selevel="", serange="", prefix=""):
        try:
            self.begin()
            self.__modify(name, roles, selevel, serange, prefix)
            self.commit()
        except ValueError as error:
            self.mylog.commit(0)
            raise error

    def __delete(self, name):
        (rc, k) = semanage_user_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, exists) = semanage_user_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if SELinux user %s is defined") % name)
        if not exists:
            raise ValueError(_("SELinux user %s is not defined") % name)

        (rc, exists) = semanage_user_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if SELinux user %s is defined") % name)
        if not exists:
            raise ValueError(_("SELinux user %s is defined in policy, cannot be deleted") % name)

        (rc, u) = semanage_user_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query user for %s") % name)
        oldserange = semanage_user_get_mlsrange(u)
        (rc, rlist) = semanage_user_get_roles(self.sh, u)
        oldserole = ",".join(rlist)

        rc = semanage_user_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete SELinux user %s") % name)

        semanage_user_key_free(k)
        semanage_user_free(u)

        self.mylog.log_remove("seuser", oldsename=name, oldserange=oldserange, oldserole=oldserole)

    def delete(self, name):
        try:
            self.begin()
            self.__delete(name)
            self.commit()

        except ValueError as error:
            self.mylog.commit(0)
            raise error

    def deleteall(self):
        (rc, ulist) = semanage_user_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list login mappings"))

        try:
            self.begin()
            for u in ulist:
                self.__delete(semanage_user_get_name(u))
            self.commit()
        except ValueError as error:
            self.mylog.commit(0)
            raise error

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.ulist) = semanage_user_list_local(self.sh)
        else:
            (rc, self.ulist) = semanage_user_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list SELinux users"))

        for u in self.ulist:
            name = semanage_user_get_name(u)
            (rc, rlist) = semanage_user_get_roles(self.sh, u)
            if rc < 0:
                raise ValueError(_("Could not list roles for user %s") % name)

            roles = " ".join(rlist)
            ddict[semanage_user_get_name(u)] = (semanage_user_get_prefix(u), semanage_user_get_mlslevel(u), semanage_user_get_mlsrange(u), roles)

        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            if ddict[k][1] or ddict[k][2]:
                l.append("-a -L %s -r %s -R '%s' %s" % (ddict[k][1], ddict[k][2], ddict[k][3], k))
            else:
                l.append("-a -R '%s' %s" % (ddict[k][3], k))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all(locallist)
        if len(ddict) == 0:
            return
        keys = sorted(ddict.keys())

        if is_mls_enabled == 1:
            if heading:
                print("\n%-15s %-10s %-10s %-30s" % ("", _("Labeling"), _("MLS/"), _("MLS/")))
                print("%-15s %-10s %-10s %-30s %s\n" % (_("SELinux User"), _("Prefix"), _("MCS Level"), _("MCS Range"), _("SELinux Roles")))
            for k in keys:
                print("%-15s %-10s %-10s %-30s %s" % (k, ddict[k][0], translate(ddict[k][1]), translate(ddict[k][2]), ddict[k][3]))
        else:
            if heading:
                print("%-15s %s\n" % (_("SELinux User"), _("SELinux Roles")))
            for k in keys:
                print("%-15s %s" % (k, ddict[k][3]))


class portRecords(semanageRecords):

    valid_types = []

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        try:
            self.valid_types = list(list(sepolicy.info(sepolicy.ATTRIBUTE, "port_type"))[0]["types"])
        except RuntimeError:
            pass

    def __genkey(self, port, proto):
        protocols = {"tcp": SEMANAGE_PROTO_TCP,
                     "udp": SEMANAGE_PROTO_UDP,
                     "sctp": SEMANAGE_PROTO_SCTP,
                     "dccp": SEMANAGE_PROTO_DCCP}

        if proto in protocols.keys():
            proto_d = protocols[proto]
        else:
            raise ValueError(_("Protocol has to be one of udp, tcp, dccp or sctp"))
        if port == "":
            raise ValueError(_("Port is required"))

        if isinstance(port, str):
            ports = port.split('-', 1)
        else:
            ports = (port,)

        if len(ports) == 1:
            high = low = int(ports[0])
        else:
            low = int(ports[0])
            high = int(ports[1])

        if high > 65535:
            raise ValueError(_("Invalid Port"))

        (rc, k) = semanage_port_key_create(self.sh, low, high, proto_d)
        if rc < 0:
            raise ValueError(_("Could not create a key for {proto}/{port}").format(proto=proto, port=port))
        return (k, proto_d, low, high)

    def __add(self, port, proto, serange, type):
        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

        if type == "":
            raise ValueError(_("Type is required"))

        type = sepolicy.get_real_type_name(type)

        if type not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a port type") % type)

        (k, proto_d, low, high) = self.__genkey(port, proto)

        (rc, p) = semanage_port_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create port for {proto}/{port}").format(proto=proto, port=port))

        semanage_port_set_proto(p, proto_d)
        semanage_port_set_range(p, low, high)
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for {proto}/{port}").format(proto=proto, port=port))

        rc = semanage_context_set_user(self.sh, con, "system_u")
        if rc < 0:
            raise ValueError(_("Could not set user in port context for {proto}/{port}").format(proto=proto, port=port))

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in port context for {proto}/{port}").format(proto=proto, port=port))

        rc = semanage_context_set_type(self.sh, con, type)
        if rc < 0:
            raise ValueError(_("Could not set type in port context for {proto}/{port}").format(proto=proto, port=port))

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_context_set_mls(self.sh, con, serange)
            if rc < 0:
                raise ValueError(_("Could not set mls fields in port context for {proto}/{port}").format(proto=proto, port=port))

        rc = semanage_port_set_con(self.sh, p, con)
        if rc < 0:
            raise ValueError(_("Could not set port context for {proto}/{port}").format(proto=proto, port=port))

        rc = semanage_port_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not add port {proto}/{port}").format(proto=proto, port=port))

        semanage_context_free(con)
        semanage_port_key_free(k)
        semanage_port_free(p)

        self.mylog.log_change("resrc=port op=add lport=%s proto=%s tcontext=%s:%s:%s:%s" % (port, socket.getprotobyname(proto), "system_u", "object_r", type, serange))

    def add(self, port, proto, serange, type):
        self.begin()
        if self.__exists(port, proto):
            print(_("Port {proto}/{port} already defined, modifying instead").format(proto=proto, port=port))
            self.__modify(port, proto, serange, type)
        else:
            self.__add(port, proto, serange, type)
        self.commit()

    def __exists(self, port, proto):
        (k, proto_d, low, high) = self.__genkey(port, proto)

        (rc, exists) = semanage_port_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if port {proto}/{port} is defined").format(proto=proto, port=port))
        semanage_port_key_free(k)

        return exists

    def __modify(self, port, proto, serange, setype):
        if serange == "" and setype == "":
            if is_mls_enabled == 1:
                raise ValueError(_("Requires setype or serange"))
            else:
                raise ValueError(_("Requires setype"))

        setype = sepolicy.get_real_type_name(setype)
        if setype and setype not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a port type") % setype)

        (k, proto_d, low, high) = self.__genkey(port, proto)

        (rc, exists) = semanage_port_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if port {proto}/{port} is defined").format(proto=proto, port=port))
        if not exists:
            raise ValueError(_("Port {proto}/{port} is not defined").format(proto=proto, port=port))

        (rc, p) = semanage_port_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query port {proto}/{port}").format(proto=proto, port=port))

        con = semanage_port_get_con(p)

        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                semanage_context_set_mls(self.sh, con, untranslate(serange))
        if setype != "":
            semanage_context_set_type(self.sh, con, setype)

        rc = semanage_port_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not modify port {proto}/{port}").format(proto=proto, port=port))

        semanage_port_key_free(k)
        semanage_port_free(p)

        self.mylog.log_change("resrc=port op=modify lport=%s proto=%s tcontext=%s:%s:%s:%s" % (port, socket.getprotobyname(proto), "system_u", "object_r", setype, serange))

    def modify(self, port, proto, serange, setype):
        self.begin()
        self.__modify(port, proto, serange, setype)
        self.commit()

    def deleteall(self):
        (rc, plist) = semanage_port_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list the ports"))

        self.begin()

        for port in plist:
            proto = semanage_port_get_proto(port)
            proto_str = semanage_port_get_proto_str(proto)
            low = semanage_port_get_low(port)
            high = semanage_port_get_high(port)
            port_str = "%s-%s" % (low, high)

            (k, proto_d, low, high) = self.__genkey(port_str, proto_str)
            if rc < 0:
                raise ValueError(_("Could not create a key for %s") % port_str)

            rc = semanage_port_del_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not delete the port %s") % port_str)
            semanage_port_key_free(k)

            if low == high:
                port_str = low

            self.mylog.log_change("resrc=port op=delete lport=%s proto=%s" % (port_str, socket.getprotobyname(proto_str)))

        self.commit()

    def __delete(self, port, proto):
        (k, proto_d, low, high) = self.__genkey(port, proto)
        (rc, exists) = semanage_port_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if port {proto}/{port} is defined").format(proto=proto, port=port))
        if not exists:
            raise ValueError(_("Port {proto}/{port} is not defined").format(proto=proto, port=port))

        (rc, exists) = semanage_port_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if port {proto}/{port} is defined").format(proto=proto, port=port))
        if not exists:
            raise ValueError(_("Port {proto}/{port} is defined in policy, cannot be deleted").format(proto=proto, port=port))

        rc = semanage_port_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete port {proto}/{port}").format(proto=proto, port=port))

        semanage_port_key_free(k)

        self.mylog.log_change("resrc=port op=delete lport=%s proto=%s" % (port, socket.getprotobyname(proto)))

    def delete(self, port, proto):
        self.begin()
        self.__delete(port, proto)
        self.commit()

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_port_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_port_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ports"))

        for port in self.plist:
            con = semanage_port_get_con(port)
            ctype = semanage_context_get_type(con)
            level = semanage_context_get_mls(con)
            proto = semanage_port_get_proto(port)
            proto_str = semanage_port_get_proto_str(proto)
            low = semanage_port_get_low(port)
            high = semanage_port_get_high(port)
            ddict[(low, high, proto_str)] = (ctype, level)
        return ddict

    def get_all_by_type(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_port_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_port_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ports"))

        for port in self.plist:
            con = semanage_port_get_con(port)
            ctype = semanage_context_get_type(con)
            proto = semanage_port_get_proto(port)
            proto_str = semanage_port_get_proto_str(proto)
            low = semanage_port_get_low(port)
            high = semanage_port_get_high(port)
            if (ctype, proto_str) not in ddict.keys():
                ddict[(ctype, proto_str)] = []
            if low == high:
                ddict[(ctype, proto_str)].append("%d" % low)
            else:
                ddict[(ctype, proto_str)].append("%d-%d" % (low, high))
        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            port = k[0] if k[0] == k[1] else "%s-%s" % (k[0], k[1])
            if ddict[k][1]:
                l.append("-a -t %s -r '%s' -p %s %s" % (ddict[k][0], ddict[k][1], k[2], port))
            else:
                l.append("-a -t %s -p %s %s" % (ddict[k][0], k[2], port))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all_by_type(locallist)
        if len(ddict) == 0:
            return
        keys = sorted(ddict.keys())

        if heading:
            print("%-30s %-8s %s\n" % (_("SELinux Port Type"), _("Proto"), _("Port Number")))
        for i in keys:
            rec = "%-30s %-8s " % i
            rec += "%s" % ddict[i][0]
            for p in ddict[i][1:]:
                rec += ", %s" % p
            print(rec)

class ibpkeyRecords(semanageRecords):

    valid_types = []

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        try:
            q = TypeQuery(SELinuxPolicy(sepolicy.get_store_policy(self.store)), attrs=["ibpkey_type"])
            self.valid_types = sorted(str(t) for t in q.results())
        except:
            pass

    def __genkey(self, pkey, subnet_prefix):
        if subnet_prefix == "":
            raise ValueError(_("Subnet Prefix is required"))

        pkeys = pkey.split("-")
        if len(pkeys) == 1:
            high = low = int(pkeys[0], 0)
        else:
            low = int(pkeys[0], 0)
            high = int(pkeys[1], 0)

        if high > 65535:
            raise ValueError(_("Invalid Pkey"))

        (rc, k) = semanage_ibpkey_key_create(self.sh, subnet_prefix, low, high)
        if rc < 0:
            raise ValueError(_("Could not create a key for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))
        return (k, subnet_prefix, low, high)

    def __add(self, pkey, subnet_prefix, serange, type):
        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

        if type == "":
            raise ValueError(_("Type is required"))

        type = sepolicy.get_real_type_name(type)

        if type not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a ibpkey type") % type)

        (k, subnet_prefix, low, high) = self.__genkey(pkey, subnet_prefix)

        (rc, p) = semanage_ibpkey_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create ibpkey for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        semanage_ibpkey_set_subnet_prefix(self.sh, p, subnet_prefix)
        semanage_ibpkey_set_range(p, low, high)
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_context_set_user(self.sh, con, "system_u")
        if rc < 0:
            raise ValueError(_("Could not set user in ibpkey context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in ibpkey context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_context_set_type(self.sh, con, type)
        if rc < 0:
            raise ValueError(_("Could not set type in ibpkey context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_context_set_mls(self.sh, con, serange)
            if rc < 0:
                raise ValueError(_("Could not set mls fields in ibpkey context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_ibpkey_set_con(self.sh, p, con)
        if rc < 0:
            raise ValueError(_("Could not set ibpkey context for {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_ibpkey_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not add ibpkey {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        semanage_context_free(con)
        semanage_ibpkey_key_free(k)
        semanage_ibpkey_free(p)

    def add(self, pkey, subnet_prefix, serange, type):
        self.begin()
        if self.__exists(pkey, subnet_prefix):
            print(_("ibpkey {subnet_prefix}/{pkey} already defined, modifying instead").format(subnet_prefix=subnet_prefix, pkey=pkey))
            self.__modify(pkey, subnet_prefix, serange, type)
        else:
            self.__add(pkey, subnet_prefix, serange, type)
        self.commit()

    def __exists(self, pkey, subnet_prefix):
        (k, subnet_prefix, low, high) = self.__genkey(pkey, subnet_prefix)

        (rc, exists) = semanage_ibpkey_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibpkey {subnet_prefix}/{pkey} is defined").formnat(subnet_prefix=subnet_prefix, pkey=pkey))
        semanage_ibpkey_key_free(k)

        return exists

    def __modify(self, pkey, subnet_prefix, serange, setype):
        if serange == "" and setype == "":
            if is_mls_enabled == 1:
                raise ValueError(_("Requires setype or serange"))
            else:
                raise ValueError(_("Requires setype"))

        setype = sepolicy.get_real_type_name(setype)

        if setype and setype not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a ibpkey type") % setype)

        (k, subnet_prefix, low, high) = self.__genkey(pkey, subnet_prefix)

        (rc, exists) = semanage_ibpkey_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibpkey {subnet_prefix}/{pkey} is defined").format(subnet_prefix=subnet_prefix, pkey=pkey))
        if not exists:
            raise ValueError(_("ibpkey {subnet_prefix}/{pkey} is not defined").format(subnet_prefix=subnet_prefix, pkey=pkey))

        (rc, p) = semanage_ibpkey_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query ibpkey {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        con = semanage_ibpkey_get_con(p)

        if (is_mls_enabled == 1) and (serange != ""):
            semanage_context_set_mls(self.sh, con, untranslate(serange))
        if setype != "":
            semanage_context_set_type(self.sh, con, setype)

        rc = semanage_ibpkey_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not modify ibpkey {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        semanage_ibpkey_key_free(k)
        semanage_ibpkey_free(p)

    def modify(self, pkey, subnet_prefix, serange, setype):
        self.begin()
        self.__modify(pkey, subnet_prefix, serange, setype)
        self.commit()

    def deleteall(self):
        (rc, plist) = semanage_ibpkey_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list the ibpkeys"))

        self.begin()

        for ibpkey in plist:
            (rc, subnet_prefix) = semanage_ibpkey_get_subnet_prefix(self.sh, ibpkey)
            low = semanage_ibpkey_get_low(ibpkey)
            high = semanage_ibpkey_get_high(ibpkey)
            pkey_str = "%s-%s" % (low, high)
            (k, subnet_prefix, low, high) = self.__genkey(pkey_str, subnet_prefix)
            if rc < 0:
                raise ValueError(_("Could not create a key for %s") % pkey_str)

            rc = semanage_ibpkey_del_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not delete the ibpkey %s") % pkey_str)
            semanage_ibpkey_key_free(k)

        self.commit()

    def __delete(self, pkey, subnet_prefix):
        (k, subnet_prefix, low, high) = self.__genkey(pkey, subnet_prefix)
        (rc, exists) = semanage_ibpkey_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibpkey {subnet_prefix}/{pkey} is defined").format(subnet_prefix=subnet_prefix, pkey=pkey))
        if not exists:
            raise ValueError(_("ibpkey {subnet_prefix}/{pkey} is not defined").format(subnet_prefix=subnet_prefix, pkey=pkey))

        (rc, exists) = semanage_ibpkey_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibpkey {subnet_prefix}/{pkey} is defined").format(subnet_prefix=subnet_prefix, pkey=pkey))
        if not exists:
            raise ValueError(_("ibpkey {subnet_prefix}/{pkey} is defined in policy, cannot be deleted").format(subnet_prefix=subnet_prefix, pkey=pkey))

        rc = semanage_ibpkey_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete ibpkey {subnet_prefix}/{pkey}").format(subnet_prefix=subnet_prefix, pkey=pkey))

        semanage_ibpkey_key_free(k)

    def delete(self, pkey, subnet_prefix):
        self.begin()
        self.__delete(pkey, subnet_prefix)
        self.commit()

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_ibpkey_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_ibpkey_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ibpkeys"))

        for ibpkey in self.plist:
            con = semanage_ibpkey_get_con(ibpkey)
            ctype = semanage_context_get_type(con)
            if ctype == "reserved_ibpkey_t":
                continue
            level = semanage_context_get_mls(con)
            (rc, subnet_prefix) = semanage_ibpkey_get_subnet_prefix(self.sh, ibpkey)
            low = semanage_ibpkey_get_low(ibpkey)
            high = semanage_ibpkey_get_high(ibpkey)
            ddict[(low, high, subnet_prefix)] = (ctype, level)
        return ddict

    def get_all_by_type(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_ibpkey_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_ibpkey_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ibpkeys"))

        for ibpkey in self.plist:
            con = semanage_ibpkey_get_con(ibpkey)
            ctype = semanage_context_get_type(con)
            (rc, subnet_prefix) = semanage_ibpkey_get_subnet_prefix(self.sh, ibpkey)
            low = semanage_ibpkey_get_low(ibpkey)
            high = semanage_ibpkey_get_high(ibpkey)
            if (ctype, subnet_prefix) not in ddict.keys():
                ddict[(ctype, subnet_prefix)] = []
            if low == high:
                ddict[(ctype, subnet_prefix)].append("0x%x" % low)
            else:
                ddict[(ctype, subnet_prefix)].append("0x%x-0x%x" % (low, high))
        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)

        for k in sorted(ddict.keys()):
            port = k[0] if k[0] == k[1] else "%s-%s" % (k[0], k[1])
            if ddict[k][1]:
                l.append("-a -t %s -r '%s' -x %s %s" % (ddict[k][0], ddict[k][1], k[2], port))
            else:
                l.append("-a -t %s -x %s %s" % (ddict[k][0], k[2], port))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all_by_type(locallist)
        keys = ddict.keys()
        if len(keys) == 0:
            return

        if heading:
            print("%-30s %-18s %s\n" % (_("SELinux IB Pkey Type"), _("Subnet_Prefix"), _("Pkey Number")))
        for i in sorted(keys):
            rec = "%-30s %-18s " % i
            rec += "%s" % ddict[i][0]
            for p in ddict[i][1:]:
                rec += ", %s" % p
            print(rec)

class ibendportRecords(semanageRecords):

    valid_types = []

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        try:
            q = TypeQuery(SELinuxPolicy(sepolicy.get_store_policy(self.store)), attrs=["ibendport_type"])
            self.valid_types = set(str(t) for t in q.results())
        except:
            pass

    def __genkey(self, ibendport, ibdev_name):
        if ibdev_name == "":
            raise ValueError(_("IB device name is required"))

        port = int(ibendport)

        if port > 255 or port < 1:
            raise ValueError(_("Invalid Port Number"))

        (rc, k) = semanage_ibendport_key_create(self.sh, ibdev_name, port)
        if rc < 0:
            raise ValueError(_("Could not create a key for ibendport {ibdev_name}/{ibendport}").format(ibdev_name=ibdev_name, ibendport=ibendport))
        return (k, ibdev_name, port)

    def __add(self, ibendport, ibdev_name, serange, type):
        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

        if type == "":
            raise ValueError(_("Type is required"))

        type = sepolicy.get_real_type_name(type)

        if type not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be an ibendport type") % type)
        (k, ibendport, port) = self.__genkey(ibendport, ibdev_name)

        (rc, p) = semanage_ibendport_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create ibendport for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        semanage_ibendport_set_ibdev_name(self.sh, p, ibdev_name)
        semanage_ibendport_set_port(p, port)
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for {ibendport}/{port}").format(ibdev_name=ibdev_name, port=port))

        rc = semanage_context_set_user(self.sh, con, "system_u")
        if rc < 0:
            raise ValueError(_("Could not set user in ibendport context for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in ibendport context for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        rc = semanage_context_set_type(self.sh, con, type)
        if rc < 0:
            raise ValueError(_("Could not set type in ibendport context for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_context_set_mls(self.sh, con, serange)
            if rc < 0:
                raise ValueError(_("Could not set mls fields in ibendport context for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        rc = semanage_ibendport_set_con(self.sh, p, con)
        if rc < 0:
            raise ValueError(_("Could not set ibendport context for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        rc = semanage_ibendport_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not add ibendport {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

        semanage_context_free(con)
        semanage_ibendport_key_free(k)
        semanage_ibendport_free(p)

    def add(self, ibendport, ibdev_name, serange, type):
        self.begin()
        if self.__exists(ibendport, ibdev_name):
            print(_("ibendport {ibdev_name}/{port} already defined, modifying instead").format(ibdev_name=ibdev_name, port=port))
            self.__modify(ibendport, ibdev_name, serange, type)
        else:
            self.__add(ibendport, ibdev_name, serange, type)
        self.commit()

    def __exists(self, ibendport, ibdev_name):
        (k, ibendport, port) = self.__genkey(ibendport, ibdev_name)

        (rc, exists) = semanage_ibendport_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibendport {ibdev_name}/{port} is defined").format(ibdev_name=ibdev_name, port=port))
        semanage_ibendport_key_free(k)

        return exists

    def __modify(self, ibendport, ibdev_name, serange, setype):
        if serange == "" and setype == "":
            if is_mls_enabled == 1:
                raise ValueError(_("Requires setype or serange"))
            else:
                raise ValueError(_("Requires setype"))

        setype = sepolicy.get_real_type_name(setype)

        if setype and setype not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be an ibendport type") % setype)

        (k, ibdev_name, port) = self.__genkey(ibendport, ibdev_name)

        (rc, exists) = semanage_ibendport_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibendport {ibdev_name}/{ibendport} is defined").format(ibdev_name=ibdev_name, ibendport=ibendport))
        if not exists:
            raise ValueError(_("ibendport {ibdev_name}/{ibendport} is not defined").format(ibdev_name=ibdev_name, ibendport=ibendport))

        (rc, p) = semanage_ibendport_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query ibendport {ibdev_name}/{ibendport}").format(ibdev_name=ibdev_name, ibendport=ibendport))

        con = semanage_ibendport_get_con(p)

        if (is_mls_enabled == 1) and (serange != ""):
            semanage_context_set_mls(self.sh, con, untranslate(serange))
        if setype != "":
            semanage_context_set_type(self.sh, con, setype)

        rc = semanage_ibendport_modify_local(self.sh, k, p)
        if rc < 0:
            raise ValueError(_("Could not modify ibendport {ibdev_name}/{ibendport}").format(ibdev_name=ibdev_name, ibendport=ibendport))

        semanage_ibendport_key_free(k)
        semanage_ibendport_free(p)

    def modify(self, ibendport, ibdev_name, serange, setype):
        self.begin()
        self.__modify(ibendport, ibdev_name, serange, setype)
        self.commit()

    def deleteall(self):
        (rc, plist) = semanage_ibendport_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list the ibendports"))

        self.begin()

        for ibendport in plist:
            (rc, ibdev_name) = semanage_ibendport_get_ibdev_name(self.sh, ibendport)
            port = semanage_ibendport_get_port(ibendport)
            (k, ibdev_name, port) = self.__genkey(str(port), ibdev_name)
            if rc < 0:
                raise ValueError(_("Could not create a key for {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))

            rc = semanage_ibendport_del_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not delete the ibendport {ibdev_name}/{port}").format(ibdev_name=ibdev_name, port=port))
            semanage_ibendport_key_free(k)

        self.commit()

    def __delete(self, ibendport, ibdev_name):
        (k, ibdev_name, port) = self.__genkey(ibendport, ibdev_name)
        (rc, exists) = semanage_ibendport_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibendport {ibdev_name}/{ibendport} is defined").format(ibdev_name=ibdev_name, ibendport=ibendport))
        if not exists:
            raise ValueError(_("ibendport {ibdev_name}/{ibendport} is not defined").format(ibdev_name=ibdev_name, ibendport=ibendport))

        (rc, exists) = semanage_ibendport_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if ibendport {ibdev_name}/{ibendport} is defined").format(ibdev_name=ibdev_name, ibendport=ibendport))
        if not exists:
            raise ValueError(_("ibendport {ibdev_name}/{ibendport} is defined in policy, cannot be deleted").format(ibdev_name=ibdev_name, ibendport=ibendport))

        rc = semanage_ibendport_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete ibendport {ibdev_name}/{ibendport}").format(ibdev_name=ibdev_name, ibendport=ibendport))

        semanage_ibendport_key_free(k)

    def delete(self, ibendport, ibdev_name):
        self.begin()
        self.__delete(ibendport, ibdev_name)
        self.commit()

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_ibendport_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_ibendport_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ibendports"))

        for ibendport in self.plist:
            con = semanage_ibendport_get_con(ibendport)
            ctype = semanage_context_get_type(con)
            if ctype == "reserved_ibendport_t":
                continue
            level = semanage_context_get_mls(con)
            (rc, ibdev_name) = semanage_ibendport_get_ibdev_name(self.sh, ibendport)
            port = semanage_ibendport_get_port(ibendport)
            ddict[(port, ibdev_name)] = (ctype, level)
        return ddict

    def get_all_by_type(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.plist) = semanage_ibendport_list_local(self.sh)
        else:
            (rc, self.plist) = semanage_ibendport_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list ibendports"))

        for ibendport in self.plist:
            con = semanage_ibendport_get_con(ibendport)
            ctype = semanage_context_get_type(con)
            (rc, ibdev_name) = semanage_ibendport_get_ibdev_name(self.sh, ibendport)
            port = semanage_ibendport_get_port(ibendport)
            if (ctype, ibdev_name) not in ddict.keys():
                ddict[(ctype, ibdev_name)] = []
            ddict[(ctype, ibdev_name)].append("0x%x" % port)
        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)

        for k in sorted(ddict.keys()):
            if ddict[k][1]:
                l.append("-a -t %s -r '%s' -z %s %s" % (ddict[k][0], ddict[k][1], k[1], k[0]))
            else:
                l.append("-a -t %s -z %s %s" % (ddict[k][0], k[1], k[0]))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all_by_type(locallist)
        keys = ddict.keys()
        if len(keys) == 0:
            return

        if heading:
            print("%-30s %-18s %s\n" % (_("SELinux IB End Port Type"), _("IB Device Name"), _("Port Number")))
        for i in sorted(keys):
            rec = "%-30s %-18s " % i
            rec += "%s" % ddict[i][0]
            for p in ddict[i][1:]:
                rec += ", %s" % p
            print(rec)

class nodeRecords(semanageRecords):

    valid_types = []

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        self.protocol = ["ipv4", "ipv6"]
        try:
            self.valid_types = list(list(sepolicy.info(sepolicy.ATTRIBUTE, "node_type"))[0]["types"])
        except RuntimeError:
            pass

    def validate(self, addr, mask, protocol):
        newaddr = addr
        newmask = mask
        newprotocol = ""

        if addr == "":
            raise ValueError(_("Node Address is required"))

        # verify that (addr, mask) is either a IP address (without a mask) or a valid network mask
        if len(mask) == 0 or mask[0] == "/":
            i = ipaddress.ip_network(addr + mask)
            newaddr = str(i.network_address)
            newmask = str(i.netmask)
            protocol = "ipv%d" % i.version

        try:
            newprotocol = self.protocol.index(protocol)
        except:
            raise ValueError(_("Unknown or missing protocol"))

        try:
            audit_protocol = socket.getprotobyname(protocol)
        except:
            # Entry for "ipv4" not found in /etc/protocols on (at
            # least) Debian? To ensure audit log compatibility, let's
            # use the same numeric value as Fedora: 4, which is
            # actually understood by kernel as IP over IP.
            if (protocol == "ipv4"):
                audit_protocol = socket.IPPROTO_IPIP
            else:
                raise ValueError(_("Unknown or missing protocol"))

        return newaddr, newmask, newprotocol, audit_protocol

    def __add(self, addr, mask, proto, serange, ctype):
        addr, mask, proto, audit_proto = self.validate(addr, mask, proto)

        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

        if ctype == "":
            raise ValueError(_("SELinux node type is required"))

        ctype = sepolicy.get_real_type_name(ctype)

        if ctype not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a node type") % ctype)

        (rc, k) = semanage_node_key_create(self.sh, addr, mask, proto)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % addr)

        (rc, node) = semanage_node_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create addr for %s") % addr)
        semanage_node_set_proto(node, proto)

        rc = semanage_node_set_addr(self.sh, node, proto, addr)
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for %s") % addr)

        rc = semanage_node_set_mask(self.sh, node, proto, mask)
        if rc < 0:
            raise ValueError(_("Could not set mask for %s") % addr)

        rc = semanage_context_set_user(self.sh, con, "system_u")
        if rc < 0:
            raise ValueError(_("Could not set user in addr context for %s") % addr)

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in addr context for %s") % addr)

        rc = semanage_context_set_type(self.sh, con, ctype)
        if rc < 0:
            raise ValueError(_("Could not set type in addr context for %s") % addr)

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_context_set_mls(self.sh, con, serange)
            if rc < 0:
                raise ValueError(_("Could not set mls fields in addr context for %s") % addr)

        rc = semanage_node_set_con(self.sh, node, con)
        if rc < 0:
            raise ValueError(_("Could not set addr context for %s") % addr)

        rc = semanage_node_modify_local(self.sh, k, node)
        if rc < 0:
            raise ValueError(_("Could not add addr %s") % addr)

        semanage_context_free(con)
        semanage_node_key_free(k)
        semanage_node_free(node)

        self.mylog.log_change("resrc=node op=add laddr=%s netmask=%s proto=%s tcontext=%s:%s:%s:%s" % (addr, mask, audit_proto, "system_u", "object_r", ctype, serange))

    def add(self, addr, mask, proto, serange, ctype):
        self.begin()
        if self.__exists(addr, mask, proto):
            print(_("Addr %s already defined, modifying instead") % addr)
            self.__modify(addr, mask, proto, serange, ctype)
        else:
            self.__add(addr, mask, proto, serange, ctype)
        self.commit()

    def __exists(self, addr, mask, proto):
        addr, mask, proto, audit_proto = self.validate(addr, mask, proto)

        (rc, k) = semanage_node_key_create(self.sh, addr, mask, proto)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % addr)

        (rc, exists) = semanage_node_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if addr %s is defined") % addr)
        semanage_node_key_free(k)

        return exists

    def __modify(self, addr, mask, proto, serange, setype):
        addr, mask, proto, audit_proto = self.validate(addr, mask, proto)

        if serange == "" and setype == "":
            raise ValueError(_("Requires setype or serange"))

        setype = sepolicy.get_real_type_name(setype)

        if setype and setype not in self.valid_types:
            raise ValueError(_("Type %s is invalid, must be a node type") % setype)

        (rc, k) = semanage_node_key_create(self.sh, addr, mask, proto)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % addr)

        (rc, exists) = semanage_node_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if addr %s is defined") % addr)
        if not exists:
            raise ValueError(_("Addr %s is not defined") % addr)

        (rc, node) = semanage_node_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query addr %s") % addr)

        con = semanage_node_get_con(node)
        if (is_mls_enabled == 1) and (serange != ""):
            semanage_context_set_mls(self.sh, con, untranslate(serange))
        if setype != "":
            semanage_context_set_type(self.sh, con, setype)

        rc = semanage_node_modify_local(self.sh, k, node)
        if rc < 0:
            raise ValueError(_("Could not modify addr %s") % addr)

        semanage_node_key_free(k)
        semanage_node_free(node)

        self.mylog.log_change("resrc=node op=modify laddr=%s netmask=%s proto=%s tcontext=%s:%s:%s:%s" % (addr, mask, audit_proto, "system_u", "object_r", setype, serange))

    def modify(self, addr, mask, proto, serange, setype):
        self.begin()
        self.__modify(addr, mask, proto, serange, setype)
        self.commit()

    def __delete(self, addr, mask, proto):
        addr, mask, proto, audit_proto = self.validate(addr, mask, proto)

        (rc, k) = semanage_node_key_create(self.sh, addr, mask, proto)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % addr)

        (rc, exists) = semanage_node_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if addr %s is defined") % addr)
        if not exists:
            raise ValueError(_("Addr %s is not defined") % addr)

        (rc, exists) = semanage_node_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if addr %s is defined") % addr)
        if not exists:
            raise ValueError(_("Addr %s is defined in policy, cannot be deleted") % addr)

        rc = semanage_node_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete addr %s") % addr)

        semanage_node_key_free(k)

        self.mylog.log_change("resrc=node op=delete laddr=%s netmask=%s proto=%s" % (addr, mask, audit_proto))

    def delete(self, addr, mask, proto):
        self.begin()
        self.__delete(addr, mask, proto)
        self.commit()

    def deleteall(self):
        (rc, nlist) = semanage_node_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not deleteall node mappings"))

        self.begin()
        for node in nlist:
            self.__delete(semanage_node_get_addr(self.sh, node)[1], semanage_node_get_mask(self.sh, node)[1], self.protocol[semanage_node_get_proto(node)])
        self.commit()

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.ilist) = semanage_node_list_local(self.sh)
        else:
            (rc, self.ilist) = semanage_node_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list addrs"))

        for node in self.ilist:
            con = semanage_node_get_con(node)
            addr = semanage_node_get_addr(self.sh, node)
            mask = semanage_node_get_mask(self.sh, node)
            proto = self.protocol[semanage_node_get_proto(node)]
            ddict[(addr[1], mask[1], proto)] = (semanage_context_get_user(con), semanage_context_get_role(con), semanage_context_get_type(con), semanage_context_get_mls(con))

        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            if ddict[k][3]:
                l.append("-a -M %s -p %s -t %s -r '%s' %s" % (k[1], k[2], ddict[k][2], ddict[k][3], k[0]))
            else:
                l.append("-a -M %s -p %s -t %s %s" % (k[1], k[2], ddict[k][2], k[0]))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all(locallist)
        if len(ddict) == 0:
            return
        keys = sorted(ddict.keys())

        if heading:
            print("%-18s %-18s %-5s %-5s\n" % ("IP Address", "Netmask", "Protocol", "Context"))
        if is_mls_enabled:
            for k in keys:
                val = ''
                for fields in k:
                    val = val + '\t' + str(fields)
                print("%-18s %-18s %-5s %s:%s:%s:%s " % (k[0], k[1], k[2], ddict[k][0], ddict[k][1], ddict[k][2], translate(ddict[k][3], False)))
        else:
            for k in keys:
                print("%-18s %-18s %-5s %s:%s:%s " % (k[0], k[1], k[2], ddict[k][0], ddict[k][1], ddict[k][2]))


class interfaceRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)

    def __add(self, interface, serange, ctype):
        if is_mls_enabled == 1:
            if serange == "":
                serange = "s0"
            else:
                serange = untranslate(serange)

        if ctype == "":
            raise ValueError(_("SELinux Type is required"))

        (rc, k) = semanage_iface_key_create(self.sh, interface)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % interface)

        (rc, iface) = semanage_iface_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create interface for %s") % interface)

        rc = semanage_iface_set_name(self.sh, iface, interface)
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for %s") % interface)

        rc = semanage_context_set_user(self.sh, con, "system_u")
        if rc < 0:
            raise ValueError(_("Could not set user in interface context for %s") % interface)

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in interface context for %s") % interface)

        rc = semanage_context_set_type(self.sh, con, ctype)
        if rc < 0:
            raise ValueError(_("Could not set type in interface context for %s") % interface)

        if (is_mls_enabled == 1) and (serange != ""):
            rc = semanage_context_set_mls(self.sh, con, serange)
            if rc < 0:
                raise ValueError(_("Could not set mls fields in interface context for %s") % interface)

        rc = semanage_iface_set_ifcon(self.sh, iface, con)
        if rc < 0:
            raise ValueError(_("Could not set interface context for %s") % interface)

        rc = semanage_iface_set_msgcon(self.sh, iface, con)
        if rc < 0:
            raise ValueError(_("Could not set message context for %s") % interface)

        rc = semanage_iface_modify_local(self.sh, k, iface)
        if rc < 0:
            raise ValueError(_("Could not add interface %s") % interface)

        semanage_context_free(con)
        semanage_iface_key_free(k)
        semanage_iface_free(iface)

        self.mylog.log_change("resrc=interface op=add netif=%s tcontext=%s:%s:%s:%s" % (interface, "system_u", "object_r", ctype, serange))

    def add(self, interface, serange, ctype):
        self.begin()
        if self.__exists(interface):
            print(_("Interface %s already defined, modifying instead") % interface)
            self.__modify(interface, serange, ctype)
        else:
            self.__add(interface, serange, ctype)
        self.commit()

    def __exists(self, interface):
        (rc, k) = semanage_iface_key_create(self.sh, interface)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % interface)

        (rc, exists) = semanage_iface_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if interface %s is defined") % interface)
        semanage_iface_key_free(k)

        return exists

    def __modify(self, interface, serange, setype):
        if serange == "" and setype == "":
            raise ValueError(_("Requires setype or serange"))

        (rc, k) = semanage_iface_key_create(self.sh, interface)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % interface)

        (rc, exists) = semanage_iface_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if interface %s is defined") % interface)
        if not exists:
            raise ValueError(_("Interface %s is not defined") % interface)

        (rc, iface) = semanage_iface_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query interface %s") % interface)

        con = semanage_iface_get_ifcon(iface)

        if (is_mls_enabled == 1) and (serange != ""):
            semanage_context_set_mls(self.sh, con, untranslate(serange))
        if setype != "":
            semanage_context_set_type(self.sh, con, setype)

        rc = semanage_iface_modify_local(self.sh, k, iface)
        if rc < 0:
            raise ValueError(_("Could not modify interface %s") % interface)

        semanage_iface_key_free(k)
        semanage_iface_free(iface)

        self.mylog.log_change("resrc=interface op=modify netif=%s tcontext=%s:%s:%s:%s" % (interface, "system_u", "object_r", setype, serange))

    def modify(self, interface, serange, setype):
        self.begin()
        self.__modify(interface, serange, setype)
        self.commit()

    def __delete(self, interface):
        (rc, k) = semanage_iface_key_create(self.sh, interface)
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % interface)

        (rc, exists) = semanage_iface_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if interface %s is defined") % interface)
        if not exists:
            raise ValueError(_("Interface %s is not defined") % interface)

        (rc, exists) = semanage_iface_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if interface %s is defined") % interface)
        if not exists:
            raise ValueError(_("Interface %s is defined in policy, cannot be deleted") % interface)

        rc = semanage_iface_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete interface %s") % interface)

        semanage_iface_key_free(k)

        self.mylog.log_change("resrc=interface op=delete netif=%s" % interface)

    def delete(self, interface):
        self.begin()
        self.__delete(interface)
        self.commit()

    def deleteall(self):
        (rc, ulist) = semanage_iface_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not delete all interface  mappings"))

        self.begin()
        for i in ulist:
            self.__delete(semanage_iface_get_name(i))
        self.commit()

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.ilist) = semanage_iface_list_local(self.sh)
        else:
            (rc, self.ilist) = semanage_iface_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list interfaces"))

        for interface in self.ilist:
            con = semanage_iface_get_ifcon(interface)
            ddict[semanage_iface_get_name(interface)] = (semanage_context_get_user(con), semanage_context_get_role(con), semanage_context_get_type(con), semanage_context_get_mls(con))

        return ddict

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            if ddict[k][3]:
                l.append("-a -t %s -r '%s' %s" % (ddict[k][2], ddict[k][3], k))
            else:
                l.append("-a -t %s %s" % (ddict[k][2], k))
        return l

    def list(self, heading=1, locallist=0):
        ddict = self.get_all(locallist)
        if len(ddict) == 0:
            return
        keys = sorted(ddict.keys())

        if heading:
            print("%-30s %s\n" % (_("SELinux Interface"), _("Context")))
        if is_mls_enabled:
            for k in keys:
                print("%-30s %s:%s:%s:%s " % (k, ddict[k][0], ddict[k][1], ddict[k][2], translate(ddict[k][3], False)))
        else:
            for k in keys:
                print("%-30s %s:%s:%s " % (k, ddict[k][0], ddict[k][1], ddict[k][2]))


class fcontextRecords(semanageRecords):

    valid_types = []

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        try:
            self.valid_types = list(list(sepolicy.info(sepolicy.ATTRIBUTE, "file_type"))[0]["types"])
            self.valid_types += list(list(sepolicy.info(sepolicy.ATTRIBUTE, "device_node"))[0]["types"])
        except RuntimeError:
            pass

        self.equiv = {}
        self.equiv_dist = {}
        self.equal_ind = False
        try:
            fd = open(selinux.selinux_file_context_subs_path(), "r")
            for i in fd.readlines():
                i = i.strip()
                if len(i) == 0:
                    continue
                if i.startswith("#"):
                    continue
                target, substitute = i.split()
                self.equiv[target] = substitute
            fd.close()
        except IOError:
            pass
        try:
            fd = open(selinux.selinux_file_context_subs_dist_path(), "r")
            for i in fd.readlines():
                i = i.strip()
                if len(i) == 0:
                    continue
                if i.startswith("#"):
                    continue
                target, substitute = i.split()
                self.equiv_dist[target] = substitute
            fd.close()
        except IOError:
            pass

    def commit(self):
        if self.equal_ind:
            subs_file = selinux.selinux_file_context_subs_path()
            tmpfile = "%s.tmp" % subs_file
            fd = open(tmpfile, "w")
            for target in self.equiv.keys():
                fd.write("%s %s\n" % (target, self.equiv[target]))
            fd.close()
            try:
                os.chmod(tmpfile, os.stat(subs_file)[stat.ST_MODE])
            except:
                pass
            os.rename(tmpfile, subs_file)
            self.equal_ind = False
        semanageRecords.commit(self)

    def add_equal(self, target, substitute):
        self.begin()
        if target != "/" and target[-1] == "/":
            raise ValueError(_("Target %s is not valid. Target is not allowed to end with '/'") % target)

        if substitute != "/" and substitute[-1] == "/":
            raise ValueError(_("Substitute %s is not valid. Substitute is not allowed to end with '/'") % substitute)

        if target in self.equiv.keys():
            print(_("Equivalence class for %s already exists, modifying instead") % target)
            self.equiv[target] = substitute
            self.equal_ind = True
            self.mylog.log_change("resrc=fcontext op=modify-equal %s %s" % (audit.audit_encode_nv_string("sglob", target, 0), audit.audit_encode_nv_string("tglob", substitute, 0)))
            self.commit()
            return

        self.validate(target)

        for fdict in (self.equiv, self.equiv_dist):
            for i in fdict:
                if i.startswith(target + "/"):
                    raise ValueError(_("File spec %s conflicts with equivalency rule '%s %s'") % (target, i, fdict[i]))

        self.mylog.log_change("resrc=fcontext op=add-equal %s %s" % (audit.audit_encode_nv_string("sglob", target, 0), audit.audit_encode_nv_string("tglob", substitute, 0)))

        self.equiv[target] = substitute
        self.equal_ind = True
        self.commit()

    def modify_equal(self, target, substitute):
        self.begin()
        if target not in self.equiv.keys():
            raise ValueError(_("Equivalence class for %s does not exist") % target)
        self.equiv[target] = substitute
        self.equal_ind = True

        self.mylog.log_change("resrc=fcontext op=modify-equal %s %s" % (audit.audit_encode_nv_string("sglob", target, 0), audit.audit_encode_nv_string("tglob", substitute, 0)))

        self.commit()

    def createcon(self, target, seuser="system_u"):
        (rc, con) = semanage_context_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create context for %s") % target)
        if seuser == "":
            seuser = "system_u"

        rc = semanage_context_set_user(self.sh, con, seuser)
        if rc < 0:
            raise ValueError(_("Could not set user in file context for %s") % target)

        rc = semanage_context_set_role(self.sh, con, "object_r")
        if rc < 0:
            raise ValueError(_("Could not set role in file context for %s") % target)

        if is_mls_enabled == 1:
            rc = semanage_context_set_mls(self.sh, con, "s0")
            if rc < 0:
                raise ValueError(_("Could not set mls fields in file context for %s") % target)

        return con

    def validate(self, target):
        if target == "" or target.find("\n") >= 0:
            raise ValueError(_("Invalid file specification"))
        if target.find(" ") != -1:
            raise ValueError(_("File specification can not include spaces"))
        for fdict in (self.equiv, self.equiv_dist):
            for i in fdict:
                if target.startswith(i + "/"):
                    t = re.sub(i, fdict[i], target)
                    raise ValueError(_("File spec %s conflicts with equivalency rule '%s %s'; Try adding '%s' instead") % (target, i, fdict[i], t))

    def __add(self, target, type, ftype="", serange="", seuser="system_u"):
        self.validate(target)

        if is_mls_enabled == 1:
            serange = untranslate(serange)

        if type == "":
            raise ValueError(_("SELinux Type is required"))

        if type != "<<none>>":
            type = sepolicy.get_real_type_name(type)
            if type not in self.valid_types:
                raise ValueError(_("Type %s is invalid, must be a file or device type") % type)

        (rc, k) = semanage_fcontext_key_create(self.sh, target, file_types[ftype])
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % target)

        (rc, fcontext) = semanage_fcontext_create(self.sh)
        if rc < 0:
            raise ValueError(_("Could not create file context for %s") % target)

        rc = semanage_fcontext_set_expr(self.sh, fcontext, target)
        if type != "<<none>>":
            con = self.createcon(target, seuser)

            rc = semanage_context_set_type(self.sh, con, type)
            if rc < 0:
                raise ValueError(_("Could not set type in file context for %s") % target)

            if (is_mls_enabled == 1) and (serange != ""):
                rc = semanage_context_set_mls(self.sh, con, serange)
                if rc < 0:
                    raise ValueError(_("Could not set mls fields in file context for %s") % target)
            rc = semanage_fcontext_set_con(self.sh, fcontext, con)
            if rc < 0:
                raise ValueError(_("Could not set file context for %s") % target)

        semanage_fcontext_set_type(fcontext, file_types[ftype])

        rc = semanage_fcontext_modify_local(self.sh, k, fcontext)
        if rc < 0:
            raise ValueError(_("Could not add file context for %s") % target)

        if type != "<<none>>":
            semanage_context_free(con)
        semanage_fcontext_key_free(k)
        semanage_fcontext_free(fcontext)

        if not seuser:
            seuser = "system_u"

        self.mylog.log_change("resrc=fcontext op=add %s ftype=%s tcontext=%s:%s:%s:%s" % (audit.audit_encode_nv_string("tglob", target, 0), ftype_to_audit[ftype], seuser, "object_r", type, serange))

    def add(self, target, type, ftype="", serange="", seuser="system_u"):
        self.begin()
        if self.__exists(target, ftype):
            print(_("File context for %s already defined, modifying instead") % target)
            self.__modify(target, type, ftype, serange, seuser)
        else:
            self.__add(target, type, ftype, serange, seuser)
        self.commit()

    def __exists(self, target, ftype):
        (rc, k) = semanage_fcontext_key_create(self.sh, target, file_types[ftype])
        if rc < 0:
            raise ValueError(_("Could not create key for %s") % target)

        (rc, exists) = semanage_fcontext_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if file context for %s is defined") % target)

        if not exists:
            (rc, exists) = semanage_fcontext_exists_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not check if file context for %s is defined") % target)
        semanage_fcontext_key_free(k)

        return exists

    def __modify(self, target, setype, ftype, serange, seuser):
        if serange == "" and setype == "" and seuser == "":
            raise ValueError(_("Requires setype, serange or seuser"))
        if setype not in ["",  "<<none>>"]:
            setype = sepolicy.get_real_type_name(setype)
            if setype not in self.valid_types:
                raise ValueError(_("Type %s is invalid, must be a file or device type") % setype)

        self.validate(target)

        (rc, k) = semanage_fcontext_key_create(self.sh, target, file_types[ftype])
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % target)

        (rc, exists) = semanage_fcontext_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if file context for %s is defined") % target)
        if exists:
            try:
                (rc, fcontext) = semanage_fcontext_query(self.sh, k)
            except OSError:
                raise ValueError(_("Could not query file context for %s") % target)
        else:
            (rc, exists) = semanage_fcontext_exists_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not check if file context for %s is defined") % target)
            if not exists:
                raise ValueError(_("File context for %s is not defined") % target)
            try:
                (rc, fcontext) = semanage_fcontext_query_local(self.sh, k)
            except OSError:
                raise ValueError(_("Could not query file context for %s") % target)

        if setype != "<<none>>":
            con = semanage_fcontext_get_con(fcontext)

            if con is None:
                con = self.createcon(target)

            if (is_mls_enabled == 1) and (serange != ""):
                semanage_context_set_mls(self.sh, con, untranslate(serange))
            if seuser != "":
                semanage_context_set_user(self.sh, con, seuser)

            if setype != "":
                semanage_context_set_type(self.sh, con, setype)

            rc = semanage_fcontext_set_con(self.sh, fcontext, con)
            if rc < 0:
                raise ValueError(_("Could not set file context for %s") % target)
        else:
            rc = semanage_fcontext_set_con(self.sh, fcontext, None)
            if rc < 0:
                raise ValueError(_("Could not set file context for %s") % target)

        rc = semanage_fcontext_modify_local(self.sh, k, fcontext)
        if rc < 0:
            raise ValueError(_("Could not modify file context for %s") % target)

        semanage_fcontext_key_free(k)
        semanage_fcontext_free(fcontext)

        if not seuser:
            seuser = "system_u"

        self.mylog.log_change("resrc=fcontext op=modify %s ftype=%s tcontext=%s:%s:%s:%s" % (audit.audit_encode_nv_string("tglob", target, 0), ftype_to_audit[ftype], seuser, "object_r", setype, serange))

    def modify(self, target, setype, ftype, serange, seuser):
        self.begin()
        self.__modify(target, setype, ftype, serange, seuser)
        self.commit()

    def deleteall(self):
        (rc, flist) = semanage_fcontext_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list the file contexts"))

        self.begin()

        for fcontext in flist:
            target = semanage_fcontext_get_expr(fcontext)
            ftype = semanage_fcontext_get_type(fcontext)
            ftype_str = semanage_fcontext_get_type_str(ftype)
            (rc, k) = semanage_fcontext_key_create(self.sh, target, file_types[ftype_str])
            if rc < 0:
                raise ValueError(_("Could not create a key for %s") % target)

            rc = semanage_fcontext_del_local(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not delete the file context %s") % target)
            semanage_fcontext_key_free(k)

            self.mylog.log_change("resrc=fcontext op=delete %s ftype=%s" % (audit.audit_encode_nv_string("tglob", target, 0), ftype_to_audit[file_type_str_to_option[ftype_str]]))

        self.equiv = {}
        self.equal_ind = True
        self.commit()

    def __delete(self, target, ftype):
        if target in self.equiv.keys():
            self.equiv.pop(target)
            self.equal_ind = True

            self.mylog.log_change("resrc=fcontext op=delete-equal %s" % (audit.audit_encode_nv_string("tglob", target, 0)))

            return

        (rc, k) = semanage_fcontext_key_create(self.sh, target, file_types[ftype])
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % target)

        (rc, exists) = semanage_fcontext_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if file context for %s is defined") % target)
        if not exists:
            (rc, exists) = semanage_fcontext_exists(self.sh, k)
            if rc < 0:
                raise ValueError(_("Could not check if file context for %s is defined") % target)
            if exists:
                raise ValueError(_("File context for %s is defined in policy, cannot be deleted") % target)
            else:
                raise ValueError(_("File context for %s is not defined") % target)

        rc = semanage_fcontext_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete file context for %s") % target)

        semanage_fcontext_key_free(k)

        self.mylog.log_change("resrc=fcontext op=delete %s ftype=%s" % (audit.audit_encode_nv_string("tglob", target, 0), ftype_to_audit[ftype]))

    def delete(self, target, ftype):
        self.begin()
        self.__delete(target, ftype)
        self.commit()

    def get_all(self, locallist=0):
        if locallist:
            (rc, self.flist) = semanage_fcontext_list_local(self.sh)
        else:
            (rc, self.flist) = semanage_fcontext_list(self.sh)
            if rc < 0:
                raise ValueError(_("Could not list file contexts"))

            (rc, fchomedirs) = semanage_fcontext_list_homedirs(self.sh)
            if rc < 0:
                raise ValueError(_("Could not list file contexts for home directories"))

            (rc, fclocal) = semanage_fcontext_list_local(self.sh)
            if rc < 0:
                raise ValueError(_("Could not list local file contexts"))

            self.flist += fchomedirs
            self.flist += fclocal

        ddict = {}
        for fcontext in self.flist:
            expr = semanage_fcontext_get_expr(fcontext)
            ftype = semanage_fcontext_get_type(fcontext)
            ftype_str = semanage_fcontext_get_type_str(ftype)
            con = semanage_fcontext_get_con(fcontext)
            if con:
                ddict[(expr, ftype_str)] = (semanage_context_get_user(con), semanage_context_get_role(con), semanage_context_get_type(con), semanage_context_get_mls(con))
            else:
                ddict[(expr, ftype_str)] = con

        return ddict

    def customized(self):
        l = []
        fcon_dict = self.get_all(True)
        for k in fcon_dict.keys():
            if fcon_dict[k]:
                if fcon_dict[k][3]:
                    l.append("-a -f %s -t %s -r '%s' '%s'" % (file_type_str_to_option[k[1]], fcon_dict[k][2], fcon_dict[k][3], k[0]))
                else:
                    l.append("-a -f %s -t %s '%s'" % (file_type_str_to_option[k[1]], fcon_dict[k][2], k[0]))

        if len(self.equiv):
            for target in self.equiv.keys():
                l.append("-a -e %s %s" % (self.equiv[target], target))
        return l

    def list(self, heading=1, locallist=0):
        fcon_dict = self.get_all(locallist)
        if len(fcon_dict) != 0:
            if heading:
                print("%-50s %-18s %s\n" % (_("SELinux fcontext"), _("type"), _("Context")))
            # do not sort local customizations since they are evaluated based on the order they where added in
            if locallist:
                fkeys = fcon_dict.keys()
            else:
                fkeys = sorted(fcon_dict.keys())
            for k in fkeys:
                if fcon_dict[k]:
                    if is_mls_enabled:
                        print("%-50s %-18s %s:%s:%s:%s " % (k[0], k[1], fcon_dict[k][0], fcon_dict[k][1], fcon_dict[k][2], translate(fcon_dict[k][3], False)))
                    else:
                        print("%-50s %-18s %s:%s:%s " % (k[0], k[1], fcon_dict[k][0], fcon_dict[k][1], fcon_dict[k][2]))
                else:
                    print("%-50s %-18s <<None>>" % (k[0], k[1]))

        if len(self.equiv_dist):
            if not locallist:
                if heading:
                    print(_("\nSELinux Distribution fcontext Equivalence \n"))
                for target in self.equiv_dist.keys():
                    print("%s = %s" % (target, self.equiv_dist[target]))
        if len(self.equiv):
            if heading:
                print(_("\nSELinux Local fcontext Equivalence \n"))

            for target in self.equiv.keys():
                print("%s = %s" % (target, self.equiv[target]))


class booleanRecords(semanageRecords):

    def __init__(self, args = None):
        semanageRecords.__init__(self, args)
        self.dict = {}
        self.dict["TRUE"] = 1
        self.dict["FALSE"] = 0
        self.dict["ON"] = 1
        self.dict["OFF"] = 0
        self.dict["1"] = 1
        self.dict["0"] = 0

        try:
            rc, self.current_booleans = selinux.security_get_boolean_names()
            rc, ptype = selinux.selinux_getpolicytype()
        except:
            self.current_booleans = []
            ptype = None

        if self.store == "" or self.store == ptype:
            self.modify_local = True
        else:
            self.modify_local = False

    def __mod(self, name, value):
        name = selinux.selinux_boolean_sub(name)

        (rc, k) = semanage_bool_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)
        (rc, exists) = semanage_bool_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if boolean %s is defined") % name)
        if not exists:
            raise ValueError(_("Boolean %s is not defined") % name)

        (rc, b) = semanage_bool_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query file context %s") % name)

        if value.upper() in self.dict:
            semanage_bool_set_value(b, self.dict[value.upper()])
        else:
            raise ValueError(_("You must specify one of the following values: %s") % ", ".join(self.dict.keys()))

        if self.modify_local and name in self.current_booleans:
            rc = semanage_bool_set_active(self.sh, k, b)
            if rc < 0:
                raise ValueError(_("Could not set active value of boolean %s") % name)
        rc = semanage_bool_modify_local(self.sh, k, b)
        if rc < 0:
            raise ValueError(_("Could not modify boolean %s") % name)
        semanage_bool_key_free(k)
        semanage_bool_free(b)

    def modify(self, name, value=None, use_file=False):
        self.begin()
        if use_file:
            fd = open(name)
            for b in fd.read().split("\n"):
                b = b.strip()
                if len(b) == 0:
                    continue

                try:
                    boolname, val = b.split("=")
                except ValueError:
                    raise ValueError(_("Bad format {filename}: Record {record}").format(filename=name, record=b))
                self.__mod(boolname.strip(), val.strip())
            fd.close()
        else:
            self.__mod(name, value)

        self.commit()

    def __delete(self, name):
        name = selinux.selinux_boolean_sub(name)

        (rc, k) = semanage_bool_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)
        (rc, exists) = semanage_bool_exists(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if boolean %s is defined") % name)
        if not exists:
            raise ValueError(_("Boolean %s is not defined") % name)

        (rc, exists) = semanage_bool_exists_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not check if boolean %s is defined") % name)
        if not exists:
            raise ValueError(_("Boolean %s is defined in policy, cannot be deleted") % name)

        rc = semanage_bool_del_local(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not delete boolean %s") % name)

        semanage_bool_key_free(k)

    def delete(self, name):
        self.begin()
        self.__delete(name)
        self.commit()

        # New transaction to reset the boolean to its default value.
        # Calling __reset_value in the same transaction as the removal of
        # local customizations does nothing
        self.begin()
        self.__reset_value(name)
        self.commit()

    def deleteall(self):
        deleted = []
        (rc, self.blist) = semanage_bool_list_local(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list booleans"))

        self.begin()

        for boolean in self.blist:
            name = semanage_bool_get_name(boolean)
            deleted.append(name)
            self.__delete(name)

        self.commit()

        # New transaction to reset all affected booleans to their default values.
        # Calling __reset_value in the same transaction as the removal of
        # local customizations does nothing
        self.begin()

        for boolean in deleted:
            self.__reset_value(boolean)

        self.commit()

    # Set active value to default
    # Note: this needs to be called in a new transaction after removing local customizations
    # in order for semanage_bool_query to fetch the default value
    # (as opposed to the current one -- set by the local customizations)
    def __reset_value(self, name):
        name = selinux.selinux_boolean_sub(name)

        (rc, k) = semanage_bool_key_create(self.sh, name)
        if rc < 0:
            raise ValueError(_("Could not create a key for %s") % name)

        (rc, b) = semanage_bool_query(self.sh, k)
        if rc < 0:
            raise ValueError(_("Could not query boolean %s") % name)

        semanage_bool_set_value(b, semanage_bool_get_value(b))

        rc = semanage_bool_set_active(self.sh, k, b)
        if rc < 0:
            raise ValueError(_("Could not set active value of boolean %s") % name)

        semanage_bool_key_free(k)
        semanage_bool_free(b)

    def get_all(self, locallist=0):
        ddict = {}
        if locallist:
            (rc, self.blist) = semanage_bool_list_local(self.sh)
        else:
            (rc, self.blist) = semanage_bool_list(self.sh)
        if rc < 0:
            raise ValueError(_("Could not list booleans"))

        for boolean in self.blist:
            value = []
            name = semanage_bool_get_name(boolean)
            value.append(semanage_bool_get_value(boolean))
            if self.modify_local and name in self.current_booleans:
                value.append(selinux.security_get_boolean_pending(name))
                value.append(selinux.security_get_boolean_active(name))
            else:
                value.append(value[0])
                value.append(value[0])
            ddict[name] = value

        return ddict

    def get_desc(self, name):
        name = selinux.selinux_boolean_sub(name)
        return sepolicy.boolean_desc(name)

    def get_category(self, name):
        name = selinux.selinux_boolean_sub(name)
        return sepolicy.boolean_category(name)

    def customized(self):
        l = []
        ddict = self.get_all(True)
        for k in sorted(ddict.keys()):
            if ddict[k]:
                l.append("-m -%s %s" % (ddict[k][2], k))
        return l

    def list(self, heading=True, locallist=False, use_file=False):
        on_off = (_("off"), _("on"))
        if use_file:
            ddict = self.get_all(locallist)
            for k in sorted(ddict.keys()):
                if ddict[k]:
                    print("%s=%s" % (k, ddict[k][2]))
            return
        ddict = self.get_all(locallist)
        if len(ddict) == 0:
            return

        if heading:
            print("%-30s %s  %s %s\n" % (_("SELinux boolean"), _("State"), _("Default"), _("Description")))
        for k in sorted(ddict.keys()):
            if ddict[k]:
                print("%-30s (%-5s,%5s)  %s" % (k, on_off[ddict[k][2]], on_off[ddict[k][0]], self.get_desc(k)))
