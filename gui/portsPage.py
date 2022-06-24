## portsPage.py - show selinux mappings
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
import sys
from gi.repository import GObject, Gtk
import seobject

TYPE_COL = 0
PROTOCOL_COL = 1
MLS_COL = 2
PORT_COL = 3

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput

from semanagePage import *

##
## I18N
##
PROGNAME = "selinux-gui"
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


class portsPage(semanagePage):

    def __init__(self, xml):
        semanagePage.__init__(self, xml, "ports", _("Network Port"))
        group_listview = xml.get_object("listViewButton")
        group_listview.connect("clicked", self.on_group_clicked)
        self.group = False
        self.ports_filter = xml.get_object("portsFilterEntry")
        self.ports_filter.connect("focus_out_event", self.filter_changed)
        self.ports_filter.connect("activate", self.filter_changed)
        self.ports_name_entry = xml.get_object("portsNameEntry")
        self.ports_protocol_combo = xml.get_object("portsProtocolCombo")
        self.ports_number_entry = xml.get_object("portsNumberEntry")
        self.ports_mls_entry = xml.get_object("portsMLSEntry")
        self.ports_add_button = xml.get_object("portsAddButton")
        self.ports_properties_button = xml.get_object("portsPropertiesButton")
        self.ports_delete_button = xml.get_object("portsDeleteButton")
        liststore = self.ports_protocol_combo.get_model()
        iter = liststore.get_iter_first()
        self.ports_protocol_combo.set_active_iter(iter)
        self.init_store()
        self.edit = True
        self.load()

    def filter_changed(self, *arg):
        filter = arg[0].get_text()
        if filter != self.filter:
            if self.edit:
                self.load(filter)
            else:
                self.group_load(filter)

    def init_store(self):
        self.store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING)
        self.view.set_model(self.store)
        self.store.set_sort_column_id(0, Gtk.SortType.ASCENDING)

        self.view.set_search_equal_func(self.search)
        col = Gtk.TreeViewColumn(_("SELinux Port\nType"), Gtk.CellRendererText(), text=TYPE_COL)
        col.set_sort_column_id(TYPE_COL)
        col.set_resizable(True)
        self.view.append_column(col)
        self.store.set_sort_column_id(TYPE_COL, Gtk.SortType.ASCENDING)

        col = Gtk.TreeViewColumn(_("Protocol"), Gtk.CellRendererText(), text=PROTOCOL_COL)
        col.set_sort_column_id(PROTOCOL_COL)
        col.set_resizable(True)
        self.view.append_column(col)

        self.mls_col = Gtk.TreeViewColumn(_("MLS/MCS\nLevel"), Gtk.CellRendererText(), text=MLS_COL)
        self.mls_col.set_resizable(True)
        self.mls_col.set_sort_column_id(MLS_COL)
        self.view.append_column(self.mls_col)

        col = Gtk.TreeViewColumn(_("Port"), Gtk.CellRendererText(), text=PORT_COL)
        col.set_sort_column_id(PORT_COL)
        col.set_resizable(True)
        self.view.append_column(col)
        self.store.set_sort_func(PORT_COL, self.sort_int, "")

    def sort_int(self, treemodel, iter1, iter2, user_data):
        try:
            p1 = int(treemodel.get_value(iter1, PORT_COL).split('-')[0])
            p2 = int(treemodel.get_value(iter2, PORT_COL).split('-')[0])
            if p1 > p2:
                return 1
            if p1 == p2:
                return 0
            return -1
        except:
            return 0

    def load(self, filter=""):
        self.filter = filter
        self.port = seobject.portRecords()
        dict = self.port.get_all(self.local)
        self.store.clear()
        for k in sorted(dict.keys()):
            if not (self.match(str(k[0]), filter) or self.match(dict[k][0], filter) or self.match(k[2], filter) or self.match(dict[k][1], filter) or self.match(dict[k][1], filter)):
                continue
            iter = self.store.append()
            if k[0] == k[1]:
                self.store.set_value(iter, PORT_COL, str(k[0]))
            else:
                rec = "%s-%s" % k[:2]
                self.store.set_value(iter, PORT_COL, rec)
            self.store.set_value(iter, TYPE_COL, dict[k][0])
            self.store.set_value(iter, PROTOCOL_COL, k[2])
            self.store.set_value(iter, MLS_COL, dict[k][1])
        self.view.get_selection().select_path((0,))

    def group_load(self, filter=""):
        self.filter = filter
        self.port = seobject.portRecords()
        dict = self.port.get_all_by_type(self.local)
        self.store.clear()
        for k in sorted(dict.keys()):
            ports_string = ", ".join(dict[k])
            if not (self.match(ports_string, filter) or self.match(k[0], filter) or self.match(k[1], filter)):
                continue
            iter = self.store.append()
            self.store.set_value(iter, TYPE_COL, k[0])
            self.store.set_value(iter, PROTOCOL_COL, k[1])
            self.store.set_value(iter, PORT_COL, ports_string)
            self.store.set_value(iter, MLS_COL, "")
        self.view.get_selection().select_path((0,))

    def propertiesDialog(self):
        if self.edit:
            semanagePage.propertiesDialog(self)

    def dialogInit(self):
        store, iter = self.view.get_selection().get_selected()
        self.ports_number_entry.set_text(store.get_value(iter, PORT_COL))
        self.ports_number_entry.set_sensitive(False)
        self.ports_protocol_combo.set_sensitive(False)
        self.ports_name_entry.set_text(store.get_value(iter, TYPE_COL))
        self.ports_mls_entry.set_text(store.get_value(iter, MLS_COL))
        protocol = store.get_value(iter, PROTOCOL_COL)
        liststore = self.ports_protocol_combo.get_model()
        iter = liststore.get_iter_first()
        while iter != None and liststore.get_value(iter, 0) != protocol:
            iter = liststore.iter_next(iter)
        if iter != None:
            self.ports_protocol_combo.set_active_iter(iter)

    def dialogClear(self):
        self.ports_number_entry.set_text("")
        self.ports_number_entry.set_sensitive(True)
        self.ports_protocol_combo.set_sensitive(True)
        self.ports_name_entry.set_text("")
        self.ports_mls_entry.set_text("s0")

    def delete(self):
        store, iter = self.view.get_selection().get_selected()
        port = store.get_value(iter, PORT_COL)
        protocol = store.get_value(iter, 1)
        try:
            self.wait()
            (rc, out) = getstatusoutput("semanage port -d -p %s %s" % (protocol, port))
            self.ready()
            if rc != 0:
                return self.error(out)
            store.remove(iter)
            self.view.get_selection().select_path((0,))
        except ValueError as e:
            self.error(e.args[0])

    def add(self):
        target = self.ports_name_entry.get_text().strip()
        mls = self.ports_mls_entry.get_text().strip()
        port_number = self.ports_number_entry.get_text().strip()
        if port_number == "":
            port_number = "1"
        for i in port_number.split("-"):
            if not i.isdigit():
                self.error(_("Port number \"%s\" is not valid.  0 < PORT_NUMBER < 65536 ") % port_number)
                return False
        list_model = self.ports_protocol_combo.get_model()
        iter = self.ports_protocol_combo.get_active_iter()
        protocol = list_model.get_value(iter, 0)
        self.wait()
        (rc, out) = getstatusoutput("semanage port -a -p %s -r %s -t %s %s" % (protocol, mls, target, port_number))
        self.ready()
        if rc != 0:
            self.error(out)
            return False
        iter = self.store.append()

        self.store.set_value(iter, TYPE_COL, target)
        self.store.set_value(iter, PORT_COL, port_number)
        self.store.set_value(iter, PROTOCOL_COL, protocol)
        self.store.set_value(iter, MLS_COL, mls)

    def modify(self):
        target = self.ports_name_entry.get_text().strip()
        mls = self.ports_mls_entry.get_text().strip()
        port_number = self.ports_number_entry.get_text().strip()
        list_model = self.ports_protocol_combo.get_model()
        iter = self.ports_protocol_combo.get_active_iter()
        protocol = list_model.get_value(iter, 0)
        self.wait()
        (rc, out) = getstatusoutput("semanage port -m -p %s -r %s -t %s %s" % (protocol, mls, target, port_number))
        self.ready()
        if rc != 0:
            self.error(out)
            return False
        store, iter = self.view.get_selection().get_selected()
        self.store.set_value(iter, TYPE_COL, target)
        self.store.set_value(iter, PORT_COL, port_number)
        self.store.set_value(iter, PROTOCOL_COL, protocol)
        self.store.set_value(iter, MLS_COL, mls)

    def on_group_clicked(self, button):
        self.ports_add_button.set_sensitive(self.group)
        self.ports_properties_button.set_sensitive(self.group)
        self.ports_delete_button.set_sensitive(self.group)
        self.mls_col.set_visible(self.group)

        self.group = not self.group
        if self.group:
            button.set_label(_("List View"))
            self.group_load(self.filter)
        else:
            button.set_label(_("Group View"))
            self.load(self.filter)

        return True
