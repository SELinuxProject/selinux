## usersPage.py - show selinux mappings
## Copyright (C) 2006,2007,2008 Red Hat, Inc.

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
try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

from gi.repository import GObject, Gtk
import seobject
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


class usersPage(semanagePage):

    def __init__(self, xml):
        semanagePage.__init__(self, xml, "users", _("SELinux User"))

        self.store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING)
        self.view.set_model(self.store)
        self.store.set_sort_column_id(0, Gtk.SortType.ASCENDING)

        col = Gtk.TreeViewColumn(_("SELinux\nUser"), Gtk.CellRendererText(), text=0)
        col.set_sort_column_id(0)
        col.set_resizable(True)
        self.view.append_column(col)

        col = Gtk.TreeViewColumn(_("MLS/\nMCS Range"), Gtk.CellRendererText(), text=1)
        col.set_resizable(True)
        self.view.append_column(col)

        col = Gtk.TreeViewColumn(_("SELinux Roles"), Gtk.CellRendererText(), text=2)
        col.set_resizable(True)
        self.view.append_column(col)

        self.load()
        self.selinuxUserEntry = xml.get_object("selinuxUserEntry")
        self.mlsRangeEntry = xml.get_object("mlsRangeEntry")
        self.selinuxRolesEntry = xml.get_object("selinuxRolesEntry")

    def load(self, filter=""):
        self.filter = filter
        self.user = seobject.seluserRecords()
        dict = self.user.get_all()
        self.store.clear()
        for k in sorted(dict.keys()):
            range = seobject.translate(dict[k][2])
            if not (self.match(k, filter) or self.match(dict[k][0], filter) or self.match(range, filter) or self.match(dict[k][3], filter)):
                continue

            iter = self.store.append()
            self.store.set_value(iter, 0, k)
            self.store.set_value(iter, 1, range)
            self.store.set_value(iter, 2, dict[k][3])
        self.view.get_selection().select_path((0,))

    def dialogInit(self):
        store, iter = self.view.get_selection().get_selected()
        self.selinuxUserEntry.set_text(store.get_value(iter, 0))
        self.selinuxUserEntry.set_sensitive(False)
        self.mlsRangeEntry.set_text(store.get_value(iter, 1))
        self.selinuxRolesEntry.set_text(store.get_value(iter, 2))

    def dialogClear(self):
        self.selinuxUserEntry.set_text("")
        self.selinuxUserEntry.set_sensitive(True)
        self.mlsRangeEntry.set_text("s0")
        self.selinuxRolesEntry.set_text("")

    def add(self):
        user = self.selinuxUserEntry.get_text()
        range = self.mlsRangeEntry.get_text()
        roles = self.selinuxRolesEntry.get_text()

        self.wait()
        (rc, out) = getstatusoutput("semanage user -a -R '%s' -r %s %s" % (roles, range, user))
        self.ready()
        if rc != 0:
            self.error(out)
            return False
        iter = self.store.append()
        self.store.set_value(iter, 0, user)
        self.store.set_value(iter, 1, range)
        self.store.set_value(iter, 2, roles)

    def modify(self):
        user = self.selinuxUserEntry.get_text()
        range = self.mlsRangeEntry.get_text()
        roles = self.selinuxRolesEntry.get_text()

        self.wait()
        (rc, out) = getstatusoutput("semanage user -m -R '%s' -r %s %s" % (roles, range, user))
        self.ready()

        if rc != 0:
            self.error(out)
            return False
        self.load(self.filter)

    def delete(self):
        store, iter = self.view.get_selection().get_selected()
        try:
            user = store.get_value(iter, 0)
            if user == "root" or user == "user_u":
                raise ValueError(_("SELinux user '%s' is required") % user)

            self.wait()
            (rc, out) = getstatusoutput("semanage user -d %s" % user)
            self.ready()
            if rc != 0:
                self.error(out)
                return False
            store.remove(iter)
            self.view.get_selection().select_path((0,))
        except ValueError as e:
            self.error(e.args[0])
