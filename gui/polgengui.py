#!/usr/bin/python3 -Es
#
# polgengui.py - GUI for SELinux Config tool in system-config-selinux
#
# Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2007-2013 Red Hat
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
import signal
import string
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import os
from gi.repository import GObject
import sys
try:
    import sepolicy
except ValueError as e:
    sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
    sys.exit(1)

import sepolicy.generate
import sepolicy.interface

try:
    from subprocess import getstatusoutput
except ImportError:
    from commands import getstatusoutput


import re


def get_all_modules():
    try:
        all_modules = []
        rc, output = getstatusoutput("semodule -l 2>/dev/null")
        if rc == 0:
            l = output.split("\n")
            for i in l:
                all_modules.append(i.split()[0])
    except:
        pass

    return all_modules


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

version = "1.0"

sys.path.append('/usr/share/system-config-selinux')
sys.path.append('.')

# From John Hunter http://www.daa.com.au/pipermail/pygtk/2003-February/004454.html


def foreach(model, path, iter, selected):
    selected.append(model.get_value(iter, 0))

##
## Pull in the Glade file
##
xml = Gtk.Builder()
xml.set_translation_domain(PROGNAME)
if os.access("polgen.ui", os.F_OK):
    xml.add_from_file("polgen.ui")
else:
    xml.add_from_file("/usr/share/system-config-selinux/polgen.ui")

FILE = 1
DIR = 2


class childWindow:
    START_PAGE = 0
    SELECT_TYPE_PAGE = 0
    APP_PAGE = 1
    EXISTING_USER_PAGE = 2
    TRANSITION_PAGE = 3
    USER_TRANSITION_PAGE = 4
    ADMIN_PAGE = 5
    ROLE_PAGE = 6
    IN_NET_PAGE = 7
    OUT_NET_PAGE = 8
    COMMON_APPS_PAGE = 9
    FILES_PAGE = 10
    BOOLEAN_PAGE = 11
    SELECT_DIR_PAGE = 12
    FINISH_PAGE = 12

    def __init__(self):
        self.xml = xml
        self.notebook = xml.get_object("notebook")
        self.label_dict = {}
        self.tooltip_dict = {}
        label = xml.get_object("select_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_user_roles_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_dir_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_domain_admin_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_in_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_out_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_common_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_manages_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("select_booleans_label")
        self.label_dict[label] = label.get_text()

        label = xml.get_object("existing_user_treeview")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("transition_treeview")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_tcp_all_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_tcp_reserved_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_tcp_unreserved_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_tcp_entry")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_udp_all_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_udp_reserved_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_udp_unreserved_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("in_udp_entry")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("out_tcp_entry")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("out_udp_entry")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("out_tcp_all_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("out_udp_all_checkbutton")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("boolean_treeview")
        self.tooltip_dict[label] = label.get_tooltip_text()

        label = xml.get_object("write_treeview")
        self.tooltip_dict[label] = label.get_tooltip_text()

        try:
            self.all_types = sepolicy.generate.get_all_types()
            self.all_modules = get_all_modules()
            self.all_roles = sepolicy.generate.get_all_roles()
            self.all_users = sepolicy.generate.get_all_users()
        except RuntimeError as e:
            self.all_types = []
            self.all_modules = []
            self.all_roles = []
            self.all_users = []
            self.error(str(e))

        self.name = ""
        handlers = {
            "on_delete_clicked": self.delete,
            "on_delete_boolean_clicked": self.delete_boolean,
            "on_exec_select_clicked": self.exec_select,
            "on_init_script_select_clicked": self.init_script_select,
            "on_add_clicked": self.add,
            "on_add_boolean_clicked": self.add_boolean,
            "on_add_dir_clicked": self.add_dir,
            "on_about_clicked": self.on_about_clicked
        }
        xml.connect_signals(handlers)
        xml.get_object("cancel_button").connect("clicked", self.quit)
        self.forward_button = xml.get_object("forward_button")
        self.forward_button.connect("clicked", self.forward)
        self.back_button = xml.get_object("back_button")
        self.back_button.connect("clicked", self.back)

        self.boolean_dialog = xml.get_object("boolean_dialog")
        self.boolean_name_entry = xml.get_object("boolean_name_entry")
        self.boolean_description_entry = xml.get_object("boolean_description_entry")

        self.pages = {}
        for i in sepolicy.generate.USERS:
            self.pages[i] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.TRANSITION_PAGE, self.ROLE_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.RUSER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.ADMIN_PAGE, self.USER_TRANSITION_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.LUSER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.TRANSITION_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.SANDBOX] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.EUSER] = [self.SELECT_TYPE_PAGE, self.EXISTING_USER_PAGE, self.TRANSITION_PAGE, self.ROLE_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]

        for i in sepolicy.generate.APPLICATIONS:
            self.pages[i] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.COMMON_APPS_PAGE, self.FILES_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]
        self.pages[sepolicy.generate.USER] = [self.SELECT_TYPE_PAGE, self.APP_PAGE, self.USER_TRANSITION_PAGE, self.IN_NET_PAGE, self.OUT_NET_PAGE, self.COMMON_APPS_PAGE, self.FILES_PAGE, self.BOOLEAN_PAGE, self.SELECT_DIR_PAGE]

        self.current_page = 0
        self.back_button.set_sensitive(0)

        self.network_buttons = {}

        self.in_tcp_all_checkbutton = xml.get_object("in_tcp_all_checkbutton")
        self.in_tcp_reserved_checkbutton = xml.get_object("in_tcp_reserved_checkbutton")
        self.in_tcp_unreserved_checkbutton = xml.get_object("in_tcp_unreserved_checkbutton")
        self.in_tcp_entry = self.xml.get_object("in_tcp_entry")
        self.network_buttons[self.in_tcp_all_checkbutton] = [self.in_tcp_reserved_checkbutton, self.in_tcp_unreserved_checkbutton, self.in_tcp_entry]

        self.out_tcp_all_checkbutton = xml.get_object("out_tcp_all_checkbutton")
        self.out_tcp_reserved_checkbutton = xml.get_object("out_tcp_reserved_checkbutton")
        self.out_tcp_unreserved_checkbutton = xml.get_object("out_tcp_unreserved_checkbutton")
        self.out_tcp_entry = self.xml.get_object("out_tcp_entry")

        self.network_buttons[self.out_tcp_all_checkbutton] = [self.out_tcp_entry]

        self.in_udp_all_checkbutton = xml.get_object("in_udp_all_checkbutton")
        self.in_udp_reserved_checkbutton = xml.get_object("in_udp_reserved_checkbutton")
        self.in_udp_unreserved_checkbutton = xml.get_object("in_udp_unreserved_checkbutton")
        self.in_udp_entry = self.xml.get_object("in_udp_entry")

        self.network_buttons[self.in_udp_all_checkbutton] = [self.in_udp_reserved_checkbutton, self.in_udp_unreserved_checkbutton, self.in_udp_entry]

        self.out_udp_all_checkbutton = xml.get_object("out_udp_all_checkbutton")
        self.out_udp_entry = self.xml.get_object("out_udp_entry")
        self.network_buttons[self.out_udp_all_checkbutton] = [self.out_udp_entry]

        for b in self.network_buttons.keys():
            b.connect("clicked", self.network_all_clicked)

        self.boolean_treeview = self.xml.get_object("boolean_treeview")
        self.boolean_store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_STRING)
        self.boolean_treeview.set_model(self.boolean_store)
        self.boolean_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Name"), Gtk.CellRendererText(), text=0)
        self.boolean_treeview.append_column(col)
        col = Gtk.TreeViewColumn(_("Description"), Gtk.CellRendererText(), text=1)
        self.boolean_treeview.append_column(col)

        self.role_treeview = self.xml.get_object("role_treeview")
        self.role_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.role_treeview.set_model(self.role_store)
        self.role_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.role_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Role"), Gtk.CellRendererText(), text=0)
        self.role_treeview.append_column(col)

        self.existing_user_treeview = self.xml.get_object("existing_user_treeview")
        self.existing_user_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.existing_user_treeview.set_model(self.existing_user_store)
        self.existing_user_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Existing_User"), Gtk.CellRendererText(), text=0)
        self.existing_user_treeview.append_column(col)

        for i in self.all_roles:
            iter = self.role_store.append()
            self.role_store.set_value(iter, 0, i[:-2])

        self.in_tcp_reserved_checkbutton = xml.get_object("in_tcp_reserved_checkbutton")

        self.transition_treeview = self.xml.get_object("transition_treeview")
        self.transition_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.transition_treeview.set_model(self.transition_store)
        self.transition_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.transition_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.transition_treeview.append_column(col)

        self.user_transition_treeview = self.xml.get_object("user_transition_treeview")
        self.user_transition_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.user_transition_treeview.set_model(self.user_transition_store)
        self.user_transition_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.user_transition_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.user_transition_treeview.append_column(col)

        for i in self.all_users:
            iter = self.user_transition_store.append()
            self.user_transition_store.set_value(iter, 0, i[:-2])
            iter = self.existing_user_store.append()
            self.existing_user_store.set_value(iter, 0, i[:-2])

        self.admin_treeview = self.xml.get_object("admin_treeview")
        self.admin_store = Gtk.ListStore(GObject.TYPE_STRING)
        self.admin_treeview.set_model(self.admin_store)
        self.admin_treeview.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.admin_store.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        col = Gtk.TreeViewColumn(_("Application"), Gtk.CellRendererText(), text=0)
        self.admin_treeview.append_column(col)

        try:
            for u in sepolicy.interface.get_user():
                iter = self.transition_store.append()
                self.transition_store.set_value(iter, 0, u)

            for a in sepolicy.interface.get_admin():
                iter = self.admin_store.append()
                self.admin_store.set_value(iter, 0, a)
        except ValueError as e:
            self.error(e.message)

    def confine_application(self):
        return self.get_type() in sepolicy.generate.APPLICATIONS

    def forward(self, arg):
        type = self.get_type()
        if self.current_page == self.START_PAGE:
            self.back_button.set_sensitive(1)

        if self.pages[type][self.current_page] == self.SELECT_TYPE_PAGE:
            if self.on_select_type_page_next():
                return

        if self.pages[type][self.current_page] == self.IN_NET_PAGE:
            if self.on_in_net_page_next():
                return

        if self.pages[type][self.current_page] == self.OUT_NET_PAGE:
            if self.on_out_net_page_next():
                return

        if self.pages[type][self.current_page] == self.APP_PAGE:
            if self.on_name_page_next():
                return

        if self.pages[type][self.current_page] == self.EXISTING_USER_PAGE:
            if self.on_existing_user_page_next():
                return

        if self.pages[type][self.current_page] == self.SELECT_DIR_PAGE:
            outputdir = self.output_entry.get_text()
            if not os.path.isdir(outputdir):
                self.error(_("%s must be a directory") % outputdir)
                return False

        if self.pages[type][self.current_page] == self.FINISH_PAGE:
            self.generate_policy()
            self.xml.get_object("cancel_button").set_label(Gtk.STOCK_CLOSE)
        else:
            self.current_page = self.current_page + 1
            self.notebook.set_current_page(self.pages[type][self.current_page])
            if self.pages[type][self.current_page] == self.FINISH_PAGE:
                self.forward_button.set_label(Gtk.STOCK_APPLY)

    def back(self, arg):
        type = self.get_type()
        if self.pages[type][self.current_page] == self.FINISH_PAGE:
            self.forward_button.set_label(Gtk.STOCK_GO_FORWARD)

        self.current_page = self.current_page - 1
        self.notebook.set_current_page(self.pages[type][self.current_page])
        if self.pages[type][self.current_page] == self.START_PAGE:
            self.back_button.set_sensitive(0)

    def network_all_clicked(self, button):
        active = button.get_active()
        for b in self.network_buttons[button]:
            b.set_sensitive(not active)

    def verify(self, message, title=""):
        dlg = Gtk.MessageDialog(None, 0, Gtk.MessageType.INFO,
                                Gtk.ButtonsType.YES_NO,
                                message)
        dlg.set_title(title)
        dlg.set_position(Gtk.WindowPosition.MOUSE)
        dlg.show_all()
        rc = dlg.run()
        dlg.destroy()
        return rc

    def info(self, message):
        dlg = Gtk.MessageDialog(None, 0, Gtk.MessageType.INFO,
                                Gtk.ButtonsType.OK,
                                message)
        dlg.set_position(Gtk.WindowPosition.MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def error(self, message):
        dlg = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
                                Gtk.ButtonsType.CLOSE,
                                message)
        dlg.set_position(Gtk.WindowPosition.MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def get_name(self):
        if self.existing_user_radiobutton.get_active():
            store, iter = self.existing_user_treeview.get_selection().get_selected()
            if iter == None:
                raise ValueError(_("You must select a user"))
            return store.get_value(iter, 0)
        else:
            return self.name_entry.get_text()

    def get_type(self):
        if self.sandbox_radiobutton.get_active():
            return sepolicy.generate.SANDBOX
        if self.cgi_radiobutton.get_active():
            return sepolicy.generate.CGI
        if self.user_radiobutton.get_active():
            return sepolicy.generate.USER
        if self.init_radiobutton.get_active():
            return sepolicy.generate.DAEMON
        if self.dbus_radiobutton.get_active():
            return sepolicy.generate.DBUS
        if self.inetd_radiobutton.get_active():
            return sepolicy.generate.INETD
        if self.login_user_radiobutton.get_active():
            return sepolicy.generate.LUSER
        if self.admin_user_radiobutton.get_active():
            return sepolicy.generate.AUSER
        if self.xwindows_user_radiobutton.get_active():
            return sepolicy.generate.XUSER
        if self.terminal_user_radiobutton.get_active():
            return sepolicy.generate.TUSER
        if self.root_user_radiobutton.get_active():
            return sepolicy.generate.RUSER
        if self.existing_user_radiobutton.get_active():
            return sepolicy.generate.EUSER

    def generate_policy(self, *args):
        outputdir = self.output_entry.get_text()
        try:
            my_policy = sepolicy.generate.policy(self.get_name(), self.get_type())

            iter = self.boolean_store.get_iter_first()
            while iter:
                my_policy.add_boolean(self.boolean_store.get_value(iter, 0), self.boolean_store.get_value(iter, 1))
                iter = self.boolean_store.iter_next(iter)

            if self.get_type() in sepolicy.generate.APPLICATIONS:
                my_policy.set_program(self.exec_entry.get_text())
                my_policy.gen_symbols()

                my_policy.set_use_syslog(self.syslog_checkbutton.get_active() == 1)
                my_policy.set_use_tmp(self.tmp_checkbutton.get_active() == 1)
                my_policy.set_use_uid(self.uid_checkbutton.get_active() == 1)
                my_policy.set_use_pam(self.pam_checkbutton.get_active() == 1)

                my_policy.set_use_dbus(self.dbus_checkbutton.get_active() == 1)
                my_policy.set_use_audit(self.audit_checkbutton.get_active() == 1)
                my_policy.set_use_terminal(self.terminal_checkbutton.get_active() == 1)
                my_policy.set_use_mail(self.mail_checkbutton.get_active() == 1)
                if self.get_type() is sepolicy.generate.DAEMON:
                    my_policy.set_init_script(self.init_script_entry.get_text())
                if self.get_type() == sepolicy.generate.USER:
                    selected = []
                    self.user_transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_users(selected)
            else:
                if self.get_type() == sepolicy.generate.RUSER:
                    selected = []
                    self.admin_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_domains(selected)
                    selected = []
                    self.user_transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_users(selected)
                else:
                    selected = []
                    self.transition_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_transition_domains(selected)

                    selected = []
                    self.role_treeview.get_selection().selected_foreach(foreach, selected)
                    my_policy.set_admin_roles(selected)

            my_policy.set_in_tcp(self.in_tcp_all_checkbutton.get_active(), self.in_tcp_reserved_checkbutton.get_active(), self.in_tcp_unreserved_checkbutton.get_active(), self.in_tcp_entry.get_text())
            my_policy.set_in_udp(self.in_udp_all_checkbutton.get_active(), self.in_udp_reserved_checkbutton.get_active(), self.in_udp_unreserved_checkbutton.get_active(), self.in_udp_entry.get_text())
            my_policy.set_out_tcp(self.out_tcp_all_checkbutton.get_active(), self.out_tcp_entry.get_text())
            my_policy.set_out_udp(self.out_udp_all_checkbutton.get_active(), self.out_udp_entry.get_text())

            iter = self.store.get_iter_first()
            while iter:
                if self.store.get_value(iter, 1) == FILE:
                    my_policy.add_file(self.store.get_value(iter, 0))
                else:
                    my_policy.add_dir(self.store.get_value(iter, 0))
                iter = self.store.iter_next(iter)

            self.info(my_policy.generate(outputdir))
            return False
        except ValueError as e:
            self.error(e.message)

    def delete(self, args):
        store, iter = self.view.get_selection().get_selected()
        if iter != None:
            store.remove(iter)
            self.view.get_selection().select_path((0,))

    def delete_boolean(self, args):
        store, iter = self.boolean_treeview.get_selection().get_selected()
        if iter != None:
            store.remove(iter)
            self.boolean_treeview.get_selection().select_path((0,))

    def add_boolean(self, type):
        self.boolean_name_entry.set_text("")
        self.boolean_description_entry.set_text("")
        rc = self.boolean_dialog.run()
        self.boolean_dialog.hide()
        if rc == Gtk.ResponseType.CANCEL:
            return
        iter = self.boolean_store.append()
        self.boolean_store.set_value(iter, 0, self.boolean_name_entry.get_text())
        self.boolean_store.set_value(iter, 1, self.boolean_description_entry.get_text())

    def __add(self, type):
        rc = self.file_dialog.run()
        self.file_dialog.hide()
        if rc == Gtk.ResponseType.CANCEL:
            return
        for i in self.file_dialog.get_filenames():
            iter = self.store.append()
            self.store.set_value(iter, 0, i)
            self.store.set_value(iter, 1, type)

    def exec_select(self, args):
        self.file_dialog.set_select_multiple(0)
        self.file_dialog.set_title(_("Select executable file to be confined."))
        self.file_dialog.set_action(Gtk.FileChooserAction.OPEN)
        self.file_dialog.set_current_folder("/usr/sbin")
        rc = self.file_dialog.run()
        self.file_dialog.hide()
        if rc == Gtk.ResponseType.CANCEL:
            return
        self.exec_entry.set_text(self.file_dialog.get_filename())

    def init_script_select(self, args):
        self.file_dialog.set_select_multiple(0)
        self.file_dialog.set_title(_("Select init script file to be confined."))
        self.file_dialog.set_action(Gtk.FileChooserAction.OPEN)
        self.file_dialog.set_current_folder("/etc/rc.d/init.d")
        rc = self.file_dialog.run()
        self.file_dialog.hide()
        if rc == Gtk.ResponseType.CANCEL:
            return
        self.init_script_entry.set_text(self.file_dialog.get_filename())

    def add(self, args):
        self.file_dialog.set_title(_("Select file(s) that confined application creates or writes"))
        self.file_dialog.set_current_folder("/")
        self.file_dialog.set_action(Gtk.FileChooserAction.OPEN)
        self.file_dialog.set_select_multiple(1)
        self.__add(FILE)

    def add_dir(self, args):
        self.file_dialog.set_title(_("Select directory(s) that the confined application owns and writes into"))
        self.file_dialog.set_current_folder("/")
        self.file_dialog.set_select_multiple(1)
        self.file_dialog.set_action(Gtk.FileChooserAction.SELECT_FOLDER)
        self.__add(DIR)

    def on_about_clicked(self, args):
        dlg = xml.get_object("about_dialog")
        dlg.run()
        dlg.hide()

    def quit(self, args):
        Gtk.main_quit()

    def setupScreen(self):
        # Bring in widgets from glade file.
        self.mainWindow = self.xml.get_object("main_window")
        self.druid = self.xml.get_object("druid")
        self.type = 0
        self.name_entry = self.xml.get_object("name_entry")
        self.name_entry.connect("insert_text", self.on_name_entry_changed)
        self.name_entry.connect("focus_out_event", self.on_focus_out_event)
        self.exec_entry = self.xml.get_object("exec_entry")
        self.exec_button = self.xml.get_object("exec_button")
        self.init_script_entry = self.xml.get_object("init_script_entry")
        self.init_script_button = self.xml.get_object("init_script_button")
        self.output_entry = self.xml.get_object("output_entry")
        self.output_entry.set_text(os.getcwd())
        self.xml.get_object("output_button").connect("clicked", self.output_button_clicked)

        self.xwindows_user_radiobutton = self.xml.get_object("xwindows_user_radiobutton")
        self.terminal_user_radiobutton = self.xml.get_object("terminal_user_radiobutton")
        self.root_user_radiobutton = self.xml.get_object("root_user_radiobutton")
        self.login_user_radiobutton = self.xml.get_object("login_user_radiobutton")
        self.admin_user_radiobutton = self.xml.get_object("admin_user_radiobutton")
        self.existing_user_radiobutton = self.xml.get_object("existing_user_radiobutton")

        self.user_radiobutton = self.xml.get_object("user_radiobutton")
        self.init_radiobutton = self.xml.get_object("init_radiobutton")
        self.inetd_radiobutton = self.xml.get_object("inetd_radiobutton")
        self.dbus_radiobutton = self.xml.get_object("dbus_radiobutton")
        self.cgi_radiobutton = self.xml.get_object("cgi_radiobutton")
        self.sandbox_radiobutton = self.xml.get_object("sandbox_radiobutton")
        self.tmp_checkbutton = self.xml.get_object("tmp_checkbutton")
        self.uid_checkbutton = self.xml.get_object("uid_checkbutton")
        self.pam_checkbutton = self.xml.get_object("pam_checkbutton")
        self.dbus_checkbutton = self.xml.get_object("dbus_checkbutton")
        self.audit_checkbutton = self.xml.get_object("audit_checkbutton")
        self.terminal_checkbutton = self.xml.get_object("terminal_checkbutton")
        self.mail_checkbutton = self.xml.get_object("mail_checkbutton")
        self.syslog_checkbutton = self.xml.get_object("syslog_checkbutton")
        self.view = self.xml.get_object("write_treeview")
        self.file_dialog = self.xml.get_object("filechooserdialog")

        self.store = Gtk.ListStore(GObject.TYPE_STRING, GObject.TYPE_INT)
        self.view.set_model(self.store)
        col = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=0)
        col.set_resizable(True)
        self.view.append_column(col)
        self.view.get_selection().select_path((0,))

    def output_button_clicked(self, *args):
        self.file_dialog.set_title(_("Select directory to generate policy files in"))
        self.file_dialog.set_action(Gtk.FileChooserAction.SELECT_FOLDER)
        self.file_dialog.set_select_multiple(0)
        rc = self.file_dialog.run()
        self.file_dialog.hide()
        if rc == Gtk.ResponseType.CANCEL:
            return
        self.output_entry.set_text(self.file_dialog.get_filename())

    def on_name_entry_changed(self, entry, text, size, position):
        if text.find(" ") >= 0:
            entry.stop_emission_by_name("insert-text")

    def on_focus_out_event(self, entry, third):
        name = entry.get_text()
        if self.name != name:
            if name in self.all_types:
                if self.verify(_("Type %s_t already defined in current policy.\nDo you want to continue?") % name, _("Verify Name")) == Gtk.ResponseType.NO:
                    entry.set_text("")
                    return False
            if name in self.all_modules:
                if self.verify(_("Module %s already loaded in current policy.\nDo you want to continue?") % name, _("Verify Name")) == Gtk.ResponseType.NO:
                    entry.set_text("")
                    return False

            file = "/etc/rc.d/init.d/" + name
            if os.path.isfile(file) and self.init_script_entry.get_text() == "":
                self.init_script_entry.set_text(file)

            file = "/usr/sbin/" + name
            if os.path.isfile(file) and self.exec_entry.get_text() == "":
                self.exec_entry.set_text(file)

        self.name = name
        return False

    def on_in_net_page_next(self, *args):
        try:
            sepolicy.generate.verify_ports(self.in_tcp_entry.get_text())
            sepolicy.generate.verify_ports(self.in_udp_entry.get_text())
        except ValueError as e:
            self.error(e.message)
            return True

    def on_out_net_page_next(self, *args):
        try:
            sepolicy.generate.verify_ports(self.out_tcp_entry.get_text())
            sepolicy.generate.verify_ports(self.out_udp_entry.get_text())
        except ValueError as e:
            self.error(e.message)
            return True

    def on_select_type_page_next(self, *args):
        self.exec_entry.set_sensitive(self.confine_application())
        self.exec_button.set_sensitive(self.confine_application())
        self.init_script_entry.set_sensitive(self.init_radiobutton.get_active())
        self.init_script_button.set_sensitive(self.init_radiobutton.get_active())

    def on_existing_user_page_next(self, *args):
        store, iter = self.view.get_selection().get_selected()
        if iter != None:
            self.error(_("You must select a user"))
            return True

    def on_name_page_next(self, *args):
        name = self.name_entry.get_text()
        if not name.isalnum():
            self.error(_("You must add a name made up of letters and numbers and containing no spaces."))
            return True

        for i in self.label_dict:
            text = '<b>%s</b>' % (self.label_dict[i] % ("'" + name + "'"))
            i.set_markup(text)

        for i in self.tooltip_dict:
            text = self.tooltip_dict[i] % ("'" + name + "'")
            i.set_tooltip_text(text)

        if self.confine_application():
            exe = self.exec_entry.get_text()
            if exe == "":
                self.error(_("You must enter a executable"))
                return True
            policy = sepolicy.generate.policy(name, self.get_type())
            policy.set_program(exe)
            policy.gen_writeable()
            policy.gen_symbols()
            for f in policy.files.keys():
                iter = self.store.append()
                self.store.set_value(iter, 0, f)
                self.store.set_value(iter, 1, FILE)

            for f in policy.dirs.keys():
                iter = self.store.append()
                self.store.set_value(iter, 0, f)
                self.store.set_value(iter, 1, DIR)
            self.tmp_checkbutton.set_active(policy.use_tmp)
            self.uid_checkbutton.set_active(policy.use_uid)
            self.pam_checkbutton.set_active(policy.use_pam)
            self.dbus_checkbutton.set_active(policy.use_dbus)
            self.audit_checkbutton.set_active(policy.use_audit)
            self.terminal_checkbutton.set_active(policy.use_terminal)
            self.mail_checkbutton.set_active(policy.use_mail)
            self.syslog_checkbutton.set_active(policy.use_syslog)

    def stand_alone(self):
        desktopName = _("Configure SELinux")

        self.setupScreen()
        self.mainWindow.connect("destroy", self.quit)

        self.mainWindow.show_all()
        Gtk.main()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    app = childWindow()
    app.stand_alone()
