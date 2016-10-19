## semanagePage.py - show selinux mappings
## Copyright (C) 2006 Red Hat, Inc.

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
import seobject

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


def idle_func():
    while gtk.events_pending():
        gtk.main_iteration()


class semanagePage:

    def __init__(self, xml, name, description):
        self.xml = xml
        self.window = self.xml.get_widget("mainWindow").get_root_window()
        self.busy_cursor = gtk.gdk.Cursor(gtk.gdk.WATCH)
        self.ready_cursor = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)

        self.local = False
        self.view = xml.get_widget("%sView" % name)
        self.dialog = xml.get_widget("%sDialog" % name)
        self.filter_entry = xml.get_widget("%sFilterEntry" % name)
        self.filter_entry.connect("focus_out_event", self.filter_changed)
        self.filter_entry.connect("activate", self.filter_changed)

        self.view.connect("row_activated", self.rowActivated)
        self.view.get_selection().connect("changed", self.itemSelected)
        self.description = description

    def wait(self):
        self.window.set_cursor(self.busy_cursor)
        idle_func()

    def ready(self):
        self.window.set_cursor(self.ready_cursor)
        idle_func()

    def get_description(self):
        return self.description

    def itemSelected(self, args):
        return

    def filter_changed(self, *arg):
        filter = arg[0].get_text()
        if filter != self.filter:
            self.load(filter)

    def search(self, model, col, key, i):
        sort_col = self.store.get_sort_column_id()[0]
        val = model.get_value(i, sort_col)
        if val.lower().startswith(key.lower()):
            return False
        return True

    def match(self, target, filter):
        try:
            f = filter.lower()
            t = target.lower()
            if t.find(f) >= 0:
                return True
        except:
            pass
        return False

    def rowActivated(self, view, row, Column):
        self.propertiesDialog()

    def verify(self, message, title=""):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_INFO,
                                gtk.BUTTONS_YES_NO,
                                message)
        dlg.set_title(title)
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()
        return rc

    def error(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR,
                                gtk.BUTTONS_CLOSE,
                                message)
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def deleteDialog(self):
        store, it = self.view.get_selection().get_selected()
        if (it is not None) and (self.verify(_("Are you sure you want to delete %s '%s'?" % (self.description, store.get_value(it, 0))), _("Delete %s" % self.description)) == gtk.RESPONSE_YES):
            self.delete()

    def use_menus(self):
        return True

    def addDialog(self):
        self.dialogClear()
        self.dialog.set_title(_("Add %s" % self.description))
        self.dialog.set_position(gtk.WIN_POS_MOUSE)

        while self.dialog.run() == gtk.RESPONSE_OK:
            try:
                if self.add() == False:
                    continue
                break
            except ValueError as e:
                self.error(e.args[0])
        self.dialog.hide()

    def propertiesDialog(self):
        self.dialogInit()
        self.dialog.set_title(_("Modify %s" % self.description))
        self.dialog.set_position(gtk.WIN_POS_MOUSE)
        while self.dialog.run() == gtk.RESPONSE_OK:
            try:
                if self.modify() == False:
                    continue
                break
            except ValueError as e:
                self.error(e.args[0])
        self.dialog.hide()

    def on_local_clicked(self, button):
        self.local = not self.local
        if self.local:
            button.set_label(_("all"))
        else:
            button.set_label(_("Customized"))

        self.load(self.filter)
        return True
