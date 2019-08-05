#!/usr/bin/python3 -Es
#
# system-config-selinux.py - GUI for SELinux Config tool in system-config-selinux
#
# Dan Walsh <dwalsh@redhat.com>
#
# Copyright 2006-2009 Red Hat, Inc.
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
import os
import signal
import sys
import gi
gi.require_version('Gtk', '3.0')
try:
    from gi.repository import Gtk
except RuntimeError as e:
    print("system-config-selinux:", e)
    print("This is a graphical application and requires DISPLAY to be set.")
    sys.exit(1)

from gi.repository import GObject
import statusPage
import booleansPage
import loginsPage
import usersPage
import portsPage
import modulesPage
import domainsPage
import fcontextPage
import selinux
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

version = "1.0"

sys.path.append('/usr/share/system-config-selinux')


##
## Pull in the Glade file
##
xml = Gtk.Builder()
xml.set_translation_domain(PROGNAME)
if os.access("system-config-selinux.ui", os.F_OK):
    xml.add_from_file("system-config-selinux.ui")
else:
    xml.add_from_file("/usr/share/system-config-selinux/system-config-selinux.ui")


class childWindow:

    def __init__(self):
        self.tabs = []
        self.xml = xml
        xml.connect_signals({
            "on_quit_activate": self.destroy,
            "on_delete_clicked": self.delete,
            "on_add_clicked": self.add,
            "on_properties_clicked": self.properties,
            "on_local_clicked": self.on_local_clicked,
            "on_policy_activate": self.policy,
            "on_logging_activate": self.logging,
            "on_about_activate": self.on_about_activate,
        })
        self.add_page(statusPage.statusPage(xml))
        if selinux.is_selinux_enabled() > 0:
            try:
                self.add_page(booleansPage.booleansPage(xml))
                self.add_page(fcontextPage.fcontextPage(xml))
                self.add_page(loginsPage.loginsPage(xml))
                self.add_page(usersPage.usersPage(xml))
                self.add_page(portsPage.portsPage(xml))
                self.add_page(modulesPage.modulesPage(xml))  # modules
                self.add_page(domainsPage.domainsPage(xml))  # domains
            except ValueError as e:
                self.error(e.message)

        self.add_menu = xml.get_object("add_menu_item")
        self.properties_menu = xml.get_object("properties_menu_item")
        self.delete_menu = xml.get_object("delete_menu_item")

    def error(self, message):
        dlg = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
                                Gtk.ButtonsType.CLOSE,
                                message)
        dlg.set_position(Gtk.WindowPosition.MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def add_page(self, page):
        self.tabs.append(page)

    def policy(self, args):
        os.spawnl(os.P_NOWAIT, "/usr/share/system-config-selinux/semanagegui.py")

    def logging(self, args):
        os.spawnl(os.P_NOWAIT, "/usr/bin/seaudit")

    def delete(self, args):
        self.tabs[self.notebook.get_current_page()].deleteDialog()

    def add(self, args):
        self.tabs[self.notebook.get_current_page()].addDialog()

    def properties(self, args):
        self.tabs[self.notebook.get_current_page()].propertiesDialog()

    def on_local_clicked(self, button):
        self.tabs[self.notebook.get_current_page()].on_local_clicked(button)

    def on_about_activate(self, args):
        dlg = xml.get_object("aboutWindow")
        dlg.run()
        dlg.hide()

    def destroy(self, args):
        Gtk.main_quit()

    def use_menus(self, use_menus):
        self.add_menu.set_sensitive(use_menus)
        self.properties_menu.set_sensitive(use_menus)
        self.delete_menu.set_sensitive(use_menus)

    def itemSelected(self, selection):
        store, rows = selection.get_selected_rows()
        if store != None and len(rows) > 0:
            self.notebook.set_current_page(rows[0][0])
            self.use_menus(self.tabs[rows[0][0]].use_menus())
        else:
            self.notebook.set_current_page(0)
            self.use_menus(self.tabs[0].use_menus())

    def setupScreen(self):
        # Bring in widgets from glade file.
        self.mainWindow = self.xml.get_object("mainWindow")
        self.notebook = self.xml.get_object("notebook")
        self.view = self.xml.get_object("selectView")
        self.view.get_selection().connect("changed", self.itemSelected)
        self.store = Gtk.ListStore(GObject.TYPE_STRING)
        self.view.set_model(self.store)
        col = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=0)
        col.set_resizable(True)
        self.view.append_column(col)

        for page in self.tabs:
            iter = self.store.append()
            self.store.set_value(iter, 0, page.get_description())
        self.view.get_selection().select_path((0,))

    def stand_alone(self):
        desktopName = _("Configure SELinux")

        self.setupScreen()

        self.mainWindow.connect("destroy", self.destroy)

        self.mainWindow.show_all()
        Gtk.main()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = childWindow()
    app.stand_alone()
