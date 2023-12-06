#!/usr/bin/python3 -EsI

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GObject
from gi.repository import GLib
import os
import selinux
from subprocess import Popen, PIPE, STDOUT


class selinux_server(dbus.service.Object):
    default_polkit_auth_required = "org.selinux.semanage"

    def __init__(self, *p, **k):
        super(selinux_server, self).__init__(*p, **k)

    def is_authorized(self, sender, action_id):
        bus = dbus.SystemBus()
        proxy = bus.get_object('org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority')
        authority = dbus.Interface(proxy, dbus_interface='org.freedesktop.PolicyKit1.Authority')
        subject = ('system-bus-name', {'name': sender})
        result = authority.CheckAuthorization(subject, action_id, {}, 1, '')
        return result[0]

    #
    # The semanage method runs a transaction on a series of semanage commands,
    # these commands can take the output of customized
    #
    @dbus.service.method("org.selinux", in_signature='s', sender_keyword="sender")
    def semanage(self, buf, sender):
        if not self.is_authorized(sender, "org.selinux.semanage"):
            raise dbus.exceptions.DBusException("Not authorized")
        p = Popen(["/usr/sbin/semanage", "import"], stdout=PIPE, stderr=PIPE, stdin=PIPE, universal_newlines=True)
        p.stdin.write(buf)
        output = p.communicate()
        if p.returncode and p.returncode != 0:
            raise dbus.exceptions.DBusException(output[1])

    #
    # The customized method will return all of the custommizations for policy
    # on the server.  This output can be used with the semanage method on
    # another server to make the two systems have duplicate policy.
    #
    @dbus.service.method("org.selinux", in_signature='', out_signature='s', sender_keyword="sender")
    def customized(self, sender):
        if not self.is_authorized(sender, "org.selinux.customized"):
            raise dbus.exceptions.DBusException("Not authorized")
        p = Popen(["/usr/sbin/semanage", "export"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        buf = p.stdout.read()
        output = p.communicate()
        if p.returncode and p.returncode != 0:
            raise OSError("Failed to read SELinux configuration: %s", output)
        return buf

    #
    # The semodule_list method will return the output of semodule --list=full, using the customized polkit,
    # since this is a readonly behaviour
    #
    @dbus.service.method("org.selinux", in_signature='', out_signature='s', sender_keyword="sender")
    def semodule_list(self, sender):
        if not self.is_authorized(sender, "org.selinux.semodule_list"):
            raise dbus.exceptions.DBusException("Not authorized")
        p = Popen(["/usr/sbin/semodule", "--list=full"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        buf = p.stdout.read()
        output = p.communicate()
        if p.returncode and p.returncode != 0:
            raise OSError("Failed to list SELinux modules: %s", output)
        return buf

    #
    # The restorecon method modifies any file path to the default system label
    #
    @dbus.service.method("org.selinux", in_signature='s', sender_keyword="sender")
    def restorecon(self, path, sender):
        if not self.is_authorized(sender, "org.selinux.restorecon"):
            raise dbus.exceptions.DBusException("Not authorized")
        selinux.restorecon(str(path), recursive=1)

    #
    # The setenforce method turns off the current enforcement of SELinux
    #
    @dbus.service.method("org.selinux", in_signature='i', sender_keyword="sender")
    def setenforce(self, value, sender):
        if not self.is_authorized(sender, "org.selinux.setenforce"):
            raise dbus.exceptions.DBusException("Not authorized")
        selinux.security_setenforce(value)

    #
    # The setenforce method turns off the current enforcement of SELinux
    #
    @dbus.service.method("org.selinux", in_signature='i', sender_keyword="sender")
    def relabel_on_boot(self, value, sender):
        if not self.is_authorized(sender, "org.selinux.relabel_on_boot"):
            raise dbus.exceptions.DBusException("Not authorized")
        if value == 1:
            fd = open("/.autorelabel", "w")
            fd.close()
        else:
            try:
                os.unlink("/.autorelabel")
            except FileNotFoundError:
                pass

    def write_selinux_config(self, enforcing=None, policy=None):
        path = selinux.selinux_path() + "config"
        backup_path = path + ".bck"
        fd = open(path)
        lines = fd.readlines()
        fd.close()
        fd = open(backup_path, "w")
        for l in lines:
            if enforcing and l.startswith("SELINUX="):
                fd.write("SELINUX=%s\n" % enforcing)
                continue
            if policy and l.startswith("SELINUXTYPE="):
                fd.write("SELINUXTYPE=%s\n" % policy)
                continue
            fd.write(l)
        fd.close()
        os.rename(backup_path, path)

    #
    # The change_default_enforcement modifies the current enforcement mode
    #
    @dbus.service.method("org.selinux", in_signature='s', sender_keyword="sender")
    def change_default_mode(self, value, sender):
        if not self.is_authorized(sender, "org.selinux.change_default_mode"):
            raise dbus.exceptions.DBusException("Not authorized")
        values = ["enforcing", "permissive", "disabled"]
        if value not in values:
            raise ValueError("Enforcement mode must be %s" % ", ".join(values))
        self.write_selinux_config(enforcing=value)

    #
    # The change_default_policy method modifies the policy type
    #
    @dbus.service.method("org.selinux", in_signature='s', sender_keyword="sender")
    def change_default_policy(self, value, sender):
        if not self.is_authorized(sender, "org.selinux.change_default_policy"):
            raise dbus.exceptions.DBusException("Not authorized")
        path = selinux.selinux_path() + value
        if os.path.isdir(path):
            return self.write_selinux_config(policy=value)
        raise ValueError("%s does not exist" % path)

if __name__ == "__main__":
    DBusGMainLoop(set_as_default=True)
    mainloop = GLib.MainLoop()

    system_bus = dbus.SystemBus()
    name = dbus.service.BusName("org.selinux", system_bus)
    server = selinux_server(system_bus, "/org/selinux/object")
    mainloop.run()
