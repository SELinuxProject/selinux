#!/usr/bin/python3

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GObject
import slip.dbus.service
from slip.dbus import polkit
import os
import selinux
from subprocess import Popen, PIPE, STDOUT


class selinux_server(slip.dbus.service.Object):
    default_polkit_auth_required = "org.selinux.semanage"

    def __init__(self, *p, **k):
        super(selinux_server, self).__init__(*p, **k)

    #
    # The semanage method runs a transaction on a series of semanage commands,
    # these commands can take the output of customized
    #
    @slip.dbus.polkit.require_auth("org.selinux.semanage")
    @dbus.service.method("org.selinux", in_signature='s')
    def semanage(self, buf):
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
    @slip.dbus.polkit.require_auth("org.selinux.customized")
    @dbus.service.method("org.selinux", in_signature='', out_signature='s')
    def customized(self):
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
    @slip.dbus.polkit.require_auth("org.selinux.semodule_list")
    @dbus.service.method("org.selinux", in_signature='', out_signature='s')
    def semodule_list(self):
        p = Popen(["/usr/sbin/semodule", "--list=full"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        buf = p.stdout.read()
        output = p.communicate()
        if p.returncode and p.returncode != 0:
            raise OSError("Failed to list SELinux modules: %s", output)
        return buf

    #
    # The restorecon method modifies any file path to the default system label
    #
    @slip.dbus.polkit.require_auth("org.selinux.restorecon")
    @dbus.service.method("org.selinux", in_signature='s')
    def restorecon(self, path):
        selinux.restorecon(str(path), recursive=1)

    #
    # The setenforce method turns off the current enforcement of SELinux
    #
    @slip.dbus.polkit.require_auth("org.selinux.setenforce")
    @dbus.service.method("org.selinux", in_signature='i')
    def setenforce(self, value):
        selinux.security_setenforce(value)

    #
    # The setenforce method turns off the current enforcement of SELinux
    #
    @slip.dbus.polkit.require_auth("org.selinux.relabel_on_boot")
    @dbus.service.method("org.selinux", in_signature='i')
    def relabel_on_boot(self, value):
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
    @slip.dbus.polkit.require_auth("org.selinux.change_default_mode")
    @dbus.service.method("org.selinux", in_signature='s')
    def change_default_mode(self, value):
        values = ["enforcing", "permissive", "disabled"]
        if value not in values:
            raise ValueError("Enforcement mode must be %s" % ", ".join(values))
        self.write_selinux_config(enforcing=value)

    #
    # The change_default_policy method modifies the policy type
    #
    @slip.dbus.polkit.require_auth("org.selinux.change_default_policy")
    @dbus.service.method("org.selinux", in_signature='s')
    def change_default_policy(self, value):
        path = selinux.selinux_path() + value
        if os.path.isdir(path):
            return self.write_selinux_config(policy=value)
        raise ValueError("%s does not exist" % path)

if __name__ == "__main__":
    mainloop = GObject.MainLoop()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    system_bus = dbus.SystemBus()
    name = dbus.service.BusName("org.selinux", system_bus)
    object = selinux_server(system_bus, "/org/selinux/object")
    slip.dbus.service.set_mainloop(mainloop)
    mainloop.run()
