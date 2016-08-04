#
# booleansPage.py - GUI for Booleans page in system-config-securitylevel
#
# Dan Walsh <dwalsh@redhat.com>
#
# Copyright 2006, 2007 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
import string
import gtk
import gtk.glade
import os
import gobject
import sys
import tempfile
import seobject
import semanagePage

INSTALLPATH = '/usr/share/system-config-selinux'
sys.path.append(INSTALLPATH)

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

ENFORCING = 0
PERMISSIVE = 1
DISABLED = 2

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

from glob import fnmatch


class Modifier:

    def __init__(self, name, on, save):
        self.on = on
        self.name = name
        self.save = save

    def set(self, value):
        self.on = value
        self.save = True

    def isOn(self):
        return self.on


class Boolean(Modifier):

    def __init__(self, name, val, save=False):
        Modifier.__init__(self, name, val, save)

ACTIVE = 0
MODULE = 1
DESC = 2
BOOLEAN = 3


class booleansPage:

    def __init__(self, xml, doDebug=None):
        self.xml = xml
        self.window = self.xml.get_widget("mainWindow").get_root_window()
        self.local = False
        self.types = []
        self.selinuxsupport = True
        self.typechanged = False
        self.doDebug = doDebug
        self.busy_cursor = gtk.gdk.Cursor(gtk.gdk.WATCH)
        self.ready_cursor = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)

        # Bring in widgets from glade file.
        self.typeHBox = xml.get_widget("typeHBox")
        self.booleanSW = xml.get_widget("booleanSW")
        self.booleansFilter = xml.get_widget("booleansFilter")
        self.booleansFilter.connect("focus_out_event", self.filter_changed)
        self.booleansFilter.connect("activate", self.filter_changed)

        self.booleansView = xml.get_widget("booleansView")
        self.typeLabel = xml.get_widget("typeLabel")
        self.modifySeparator = xml.get_widget("modifySeparator")

        self.revertButton = xml.get_widget("booleanRevertButton")
        self.revertButton.set_sensitive(self.local)
        self.revertButton.connect("clicked", self.on_revert_clicked)
        listStore = gtk.ListStore(gobject.TYPE_STRING)
        cell = gtk.CellRendererText()

        self.store = gtk.ListStore(gobject.TYPE_BOOLEAN, gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.store.set_sort_column_id(1, gtk.SORT_ASCENDING)
        self.booleansView.set_model(self.store)

        checkbox = gtk.CellRendererToggle()
        checkbox.connect("toggled", self.boolean_toggled)
        col = gtk.TreeViewColumn('Active', checkbox, active=ACTIVE)
        col.set_clickable(True)
        col.set_sort_column_id(ACTIVE)
        self.booleansView.append_column(col)

        col = gtk.TreeViewColumn("Module", gtk.CellRendererText(), text=MODULE)
        col.set_sort_column_id(MODULE)
        col.set_resizable(True)
        self.booleansView.append_column(col)

        col = gtk.TreeViewColumn("Description", gtk.CellRendererText(), text=DESC)
        col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        col.set_fixed_width(400)
        col.set_sort_column_id(DESC)
        col.set_resizable(True)
        self.booleansView.append_column(col)

        col = gtk.TreeViewColumn("Name", gtk.CellRendererText(), text=BOOLEAN)
        col.set_sort_column_id(BOOLEAN)
        col.set_resizable(True)
        self.booleansView.set_search_equal_func(self.__search)
        self.booleansView.append_column(col)
        self.filter = ""
        self.load(self.filter)

    def error(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR,
                                gtk.BUTTONS_CLOSE,
                                message)
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def __search(self, model, col, key, i):
        sort_col = self.store.get_sort_column_id()[0]
        if sort_col > 0:
            val = model.get_value(i, sort_col)
            if val.lower().startswith(key.lower()):
                return False
        return True

    def wait(self):
        self.window.set_cursor(self.busy_cursor)
        semanagePage.idle_func()

    def ready(self):
        self.window.set_cursor(self.ready_cursor)
        semanagePage.idle_func()

    def deleteDialog(self):
        store, iter = self.booleansView.get_selection().get_selected()
        if iter == None:
            return
        boolean = store.get_value(iter, BOOLEAN)
        # change cursor
        if boolean == None:
            return
        try:
            self.wait()
            (rc, out) = getstatusoutput("semanage boolean -d %s" % boolean)

            self.ready()
            if rc != 0:
                return self.error(out)
            self.load(self.filter)
        except ValueError as e:
            self.error(e.args[0])

    def filter_changed(self, *arg):
        filter = arg[0].get_text()
        if filter != self.filter:
            self.load(filter)
            self.filter = filter

    def use_menus(self):
        return False

    def get_description(self):
        return _("Boolean")

    def match(self, key, filter=""):
        try:
            f = filter.lower()
            cat = self.booleans.get_category(key).lower()
            val = self.booleans.get_desc(key).lower()
            k = key.lower()
            return val.find(f) >= 0 or k.find(f) >= 0 or cat.find(f) >= 0
        except:
            return False

    def load(self, filter=None):
        self.store.clear()
        self.booleans = seobject.booleanRecords()
        booleansList = self.booleans.get_all(self.local)
        for name in booleansList:
            rec = booleansList[name]
            if self.match(name, filter):
                iter = self.store.append()
                self.store.set_value(iter, ACTIVE, rec[2] == 1)
                self.store.set_value(iter, MODULE, self.booleans.get_category(name))
                self.store.set_value(iter, DESC, self.booleans.get_desc(name))
                self.store.set_value(iter, BOOLEAN, name)

    def boolean_toggled(self, widget, row):
        iter = self.store.get_iter(row)
        val = self.store.get_value(iter, ACTIVE)
        key = self.store.get_value(iter, BOOLEAN)
        self.store.set_value(iter, ACTIVE, not val)
        self.wait()
        setsebool = "/usr/sbin/setsebool -P %s %d" % (key, not val)
        rc, out = getstatusoutput(setsebool)
        if rc != 0:
            self.error(out)
        self.load(self.filter)
        self.ready()

    def on_revert_clicked(self, button):
        self.wait()
        setsebool = "semanage boolean --deleteall"
        getstatusoutput(setsebool)
        self.load(self.filter)
        self.ready()

    def on_local_clicked(self, button):
        self.local = not self.local
        self.revertButton.set_sensitive(self.local)

        if self.local:
            button.set_label(_("all"))
        else:
            button.set_label(_("Customized"))

        self.load(self.filter)
        return True
