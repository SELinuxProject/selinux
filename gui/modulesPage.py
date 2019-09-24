## modulesPage.py - show selinux mappings
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
import sys
from subprocess import Popen, PIPE
try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

from gi.repository import GObject, Gtk
import selinux
from semanagePage import *

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


class modulesPage(semanagePage):

    def __init__(self, xml):
        semanagePage.__init__(self, xml, "modules", _("Policy Module"))
        self.module_filter = xml.get_object("modulesFilterEntry")
        self.module_filter.connect("focus_out_event", self.filter_changed)
        self.module_filter.connect("activate", self.filter_changed)
        self.audit_enabled = False

        self.store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING,
                                   GObject.TYPE_STRING)
        self.view.set_model(self.store)
        self.store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Module Name"), Gtk.CellRendererText(), text=0)
        col.set_sort_column_id(0)
        col.set_resizable(True)
        self.view.append_column(col)
        self.store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Priority"), Gtk.CellRendererText(), text=1)
        self.enable_audit_button = xml.get_object("enableAuditButton")
        self.enable_audit_button.connect("clicked", self.enable_audit)
        self.new_button = xml.get_object("newModuleButton")
        self.new_button.connect("clicked", self.new_module)
        col.set_sort_column_id(1)
        col.set_resizable(True)
        self.view.append_column(col)
        self.store.set_sort_column_id(2, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Kind"), Gtk.CellRendererText(), text=2)
        col.set_sort_column_id(2)
        col.set_resizable(True)
        self.view.append_column(col)
        self.store.set_sort_func(1, self.sort_int, "")
        status, self.policy_type = selinux.selinux_getpolicytype()

        self.load()

    def sort_int(self, treemodel, iter1, iter2, user_data):
        try:
            p1 = int(treemodel.get_value(iter1, 1))
            p2 = int(treemodel.get_value(iter1, 1))
            if p1 > p2:
                return 1
            if p1 == p2:
                return 0
            return -1
        except:
            return 0

    def load(self, filter=""):
        self.filter = filter
        self.store.clear()
        try:
            fd = Popen("semodule -lfull", shell=True, stdout=PIPE).stdout
            l = fd.readlines()
            fd.close()
            for i in l:
                priority, module, kind = i.decode('utf-8').split()
                if not (self.match(module, filter) or self.match(priority, filter)):
                    continue
                iter = self.store.append()
                self.store.set_value(iter, 0, module.strip())
                self.store.set_value(iter, 1, priority.strip())
                self.store.set_value(iter, 2, kind.strip())
        except:
            pass
        self.view.get_selection().select_path((0,))

    def new_module(self, args):
        try:
            Popen(["selinux-polgengui"])
        except ValueError as e:
            self.error(e.args[0])

    def delete(self):
        store, iter = self.view.get_selection().get_selected()
        module = store.get_value(iter, 0)
        priority = store.get_value(iter, 1)
        try:
            self.wait()
            status, output = getstatusoutput("semodule -X %s -r %s" % (priority, module))
            self.ready()
            if status != 0:
                self.error(output)
            else:
                store.remove(iter)
                self.view.get_selection().select_path((0,))

        except ValueError as e:
            self.error(e.args[0])

    def enable_audit(self, button):
        self.audit_enabled = not self.audit_enabled
        try:
            self.wait()
            if self.audit_enabled:
                status, output = getstatusoutput("semodule -DB")
                button.set_label(_("Disable Audit"))
            else:
                status, output = getstatusoutput("semodule -B")
                button.set_label(_("Enable Audit"))
            self.ready()

            if status != 0:
                self.error(output)

        except ValueError as e:
            self.error(e.args[0])

    def disable_audit(self, button):
        try:
            self.wait()
            status, output = getstatusoutput("semodule -B")
            self.ready()
            if status != 0:
                self.error(output)

        except ValueError as e:
            self.error(e.args[0])

    def propertiesDialog(self):
        # Do nothing
        return

    def addDialog(self):
        dialog = Gtk.FileChooserDialog(_("Load Policy Module"),
                                       None,
                                       Gtk.FileChooserAction.OPEN,
                                       (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                                        Gtk.STOCK_OPEN, Gtk.ResponseType.OK))
        dialog.set_default_response(Gtk.ResponseType.OK)

        filter = Gtk.FileFilter()
        filter.set_name("Policy Files")
        filter.add_pattern("*.pp")
        dialog.add_filter(filter)

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            self.add(dialog.get_filename())
        dialog.destroy()

    def add(self, file):
        try:
            self.wait()
            status, output = getstatusoutput("semodule -i %s" % file)
            self.ready()
            if status != 0:
                self.error(output)
            else:
                self.load()

        except ValueError as e:
            self.error(e.args[0])
