# statusPage.py - show selinux status
## Copyright (C) 2006-2009 Red Hat, Inc.

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

## Author: Dan Walsh
import string
import gtk
import gtk.glade
import os
import gobject
import sys
import tempfile
import selinux

INSTALLPATH = '/usr/share/system-config-selinux'
sys.path.append(INSTALLPATH)

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

ENFORCING = 1
PERMISSIVE = 0
DISABLED = -1
modearray = ("disabled", "permissive", "enforcing")

SELINUXDIR = "/etc/selinux/"
RELABELFILE = "/.autorelabel"

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


class statusPage:

    def __init__(self, xml):
        self.xml = xml
        self.needRelabel = False

        self.type = selinux.selinux_getpolicytype()
        # Bring in widgets from glade file.
        self.typeHBox = xml.get_widget("typeHBox")
        self.selinuxTypeOptionMenu = xml.get_widget("selinuxTypeOptionMenu")
        self.typeLabel = xml.get_widget("typeLabel")
        self.enabledOptionMenu = xml.get_widget("enabledOptionMenu")
        self.currentOptionMenu = xml.get_widget("currentOptionMenu")
        self.relabel_checkbutton = xml.get_widget("relabelCheckbutton")
        self.relabel_checkbutton.set_active(self.is_relabel())
        self.relabel_checkbutton.connect("toggled", self.on_relabel_toggle)
        if self.get_current_mode() == ENFORCING or self.get_current_mode() == PERMISSIVE:
            self.currentOptionMenu.append_text(_("Permissive"))
            self.currentOptionMenu.append_text(_("Enforcing"))
            self.currentOptionMenu.set_active(self.get_current_mode())
            self.currentOptionMenu.connect("changed", self.set_current_mode)
            self.currentOptionMenu.set_sensitive(True)
        else:
            self.currentOptionMenu.append_text(_("Disabled"))
            self.currentOptionMenu.set_active(0)
            self.currentOptionMenu.set_sensitive(False)

        if self.read_selinux_config() == None:
            self.selinuxsupport = False
        else:
            self.enabledOptionMenu.connect("changed", self.enabled_changed)
        #
        # This line must come after read_selinux_config
        #
        self.selinuxTypeOptionMenu.connect("changed", self.typemenu_changed)

        self.typeLabel.set_mnemonic_widget(self.selinuxTypeOptionMenu)

    def use_menus(self):
        return False

    def get_description(self):
        return _("Status")

    def get_current_mode(self):
        if selinux.is_selinux_enabled():
            if selinux.security_getenforce() > 0:
                return ENFORCING
            else:
                return PERMISSIVE
        else:
            return DISABLED

    def set_current_mode(self, menu):
        selinux.security_setenforce(menu.get_active() == 1)

    def is_relabel(self):
        return os.access(RELABELFILE, os.F_OK) != 0

    def on_relabel_toggle(self, button):
        if button.get_active():
            fd = open(RELABELFILE, "w")
            fd.close()
        else:
            if os.access(RELABELFILE, os.F_OK) != 0:
                os.unlink(RELABELFILE)

    def verify(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO,
                                gtk.BUTTONS_YES_NO,
                                message)
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()
        return rc

    def typemenu_changed(self, menu):
        type = self.get_type()
        enabled = self.enabledOptionMenu.get_active()
        if self.initialtype != type:
            if self.verify(_("Changing the policy type will cause a relabel of the entire file system on the next boot. Relabeling takes a long time depending on the size of the file system.  Do you wish to continue?")) == gtk.RESPONSE_NO:
                menu.set_active(self.typeHistory)
                return None

            self.relabel_checkbutton.set_active(True)

        self.write_selinux_config(modearray[enabled], type)
        self.typeHistory = menu.get_active()

    def enabled_changed(self, combo):
        enabled = combo.get_active()
        type = self.get_type()

        if self.initEnabled != DISABLED and enabled == DISABLED:
            if self.verify(_("Changing to SELinux disabled requires a reboot.  It is not recommended.  If you later decide to turn SELinux back on, the system will be required to relabel.  If you just want to see if SELinux is causing a problem on your system, you can go to permissive mode which will only log errors and not enforce SELinux policy.  Permissive mode does not require a reboot    Do you wish to continue?")) == gtk.RESPONSE_NO:
                combo.set_active(self.enabled)
                return None

        if self.initEnabled == DISABLED and enabled < 2:
            if self.verify(_("Changing to SELinux enabled will cause a relabel of the entire file system on the next boot. Relabeling takes a long time depending on the size of the file system.  Do you wish to continue?")) == gtk.RESPONSE_NO:
                combo.set_active(self.enabled)
                return None
            self.relabel_checkbutton.set_active(True)

        self.write_selinux_config(modearray[enabled], type)
        self.enabled = enabled

    def write_selinux_config(self, enforcing, type):
        path = selinux.selinux_path() + "config"
        backup_path = path + ".bck"
        fd = open(path)
        lines = fd.readlines()
        fd.close()
        fd = open(backup_path, "w")
        for l in lines:
            if l.startswith("SELINUX="):
                fd.write("SELINUX=%s\n" % enforcing)
                continue
            if l.startswith("SELINUXTYPE="):
                fd.write("SELINUXTYPE=%s\n" % type)
                continue
            fd.write(l)
        fd.close()
        os.rename(backup_path, path)

    def read_selinux_config(self):
        self.initialtype = selinux.selinux_getpolicytype()[1]
        try:
            self.initEnabled = selinux.selinux_getenforcemode()[1]
        except:
            self.initEnabled = False
            pass
        self.enabled = self.initEnabled
        self.enabledOptionMenu.set_active(self.enabled + 1)

        self.types = []

        n = 0
        current = n

        for i in os.listdir(SELINUXDIR):
            if os.path.isdir(SELINUXDIR + i) and os.path.isdir(SELINUXDIR + i + "/policy"):
                self.types.append(i)
                self.selinuxTypeOptionMenu.append_text(i)
                if i == self.initialtype:
                    current = n
                n = n + 1
        self.selinuxTypeOptionMenu.set_active(current)
        self.typeHistory = current

        return 0

    def get_type(self):
        return self.types[self.selinuxTypeOptionMenu.get_active()]
