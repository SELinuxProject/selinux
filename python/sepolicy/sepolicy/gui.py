#!/usr/bin/python -Es
#
# Copyright (C) 2013 Red Hat
# see file 'COPYING' for use and warranty information
#
# selinux gui is a tool for the examining and modifying SELinux policy
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
#                                        02111-1307  USA
#
#    author: Ryan Hallisey rhallisey@redhat.com
#    author: Dan Walsh dwalsh@redhat.com
#    author: Miroslav Grepl mgrepl@redhat.com
#
#

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from gi.repository import Gdk
from gi.repository import GLib
from sepolicy.sedbus import SELinuxDBus
import sys
import sepolicy
import selinux
from selinux import DISABLED, PERMISSIVE, ENFORCING
import sepolicy.network
import sepolicy.manpage
import dbus
import os
import re
import unicodedata

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

reverse_file_type_str = {}
for f in sepolicy.file_type_str:
    reverse_file_type_str[sepolicy.file_type_str[f]] = f

enabled = [_("No"), _("Yes")]
action = [_("Disable"), _("Enable")]


def cmp(a, b):
    if a is None and b is None:
        return 0
    if a is None:
        return -1
    if b is None:
        return 1
    return (a > b) - (a < b)

import distutils.sysconfig
ADVANCED_LABEL = (_("Advanced >>"), _("Advanced <<"))
ADVANCED_SEARCH_LABEL = (_("Advanced Search >>"), _("Advanced Search <<"))
OUTBOUND_PAGE = 0
INBOUND_PAGE = 1

TRANSITIONS_FROM_PAGE = 0
TRANSITIONS_TO_PAGE = 1
TRANSITIONS_FILE_PAGE = 2

EXE_PAGE = 0
WRITABLE_PAGE = 1
APP_PAGE = 2

BOOLEANS_PAGE = 0
FILES_PAGE = 1
NETWORK_PAGE = 2
TRANSITIONS_PAGE = 3
LOGIN_PAGE = 4
USER_PAGE = 5
LOCKDOWN_PAGE = 6
SYSTEM_PAGE = 7
FILE_EQUIV_PAGE = 8
START_PAGE = 9

keys = ["boolean", "fcontext", "fcontext-equiv", "port", "login", "user", "module", "node", "interface"]

DISABLED_TEXT = _("""<small>
To change from Disabled to Enforcing mode
- Change the system mode from Disabled to Permissive
- Reboot, so that the system can relabel
- Once the system is working as planned
  * Change the system mode to Enforcing</small>
""")


class SELinuxGui():

    def __init__(self, app=None, test=False):
        self.finish_init = False
        self.advanced_init = True
        self.opage = START_PAGE
        self.dbus = SELinuxDBus()
        try:
            customized = self.dbus.customized()
        except dbus.exceptions.DBusException as e:
            print(e)
            self.quit()

        self.init_cur()
        self.application = app
        self.filter_txt = ""
        builder = Gtk.Builder()  # BUILDER OBJ
        self.code_path = distutils.sysconfig.get_python_lib(plat_specific=False) + "/sepolicy/"
        glade_file = self.code_path + "sepolicy.glade"
        builder.add_from_file(glade_file)
        self.outer_notebook = builder.get_object("outer_notebook")
        self.window = builder.get_object("SELinux_window")
        self.main_selection_window = builder.get_object("Main_selection_menu")
        self.main_advanced_label = builder.get_object("main_advanced_label")
        self.popup = 0
        self.applications_selection_button = builder.get_object("applications_selection_button")
        self.revert_button = builder.get_object("Revert_button")
        self.busy_cursor = Gdk.Cursor(Gdk.CursorType.WATCH)
        self.ready_cursor = Gdk.Cursor(Gdk.CursorType.LEFT_PTR)
        self.initialtype = selinux.selinux_getpolicytype()[1]
        self.current_popup = None
        self.import_export = None
        self.clear_entry = True
        self.files_add = False
        self.network_add = False

        self.all_domains = []
        self.installed_list = []
        self.previously_modified = {}

        # file dialog
        self.file_dialog = builder.get_object("add_path_dialog")
        # Error check ***************************************
        self.error_check_window = builder.get_object("error_check_window")
        self.error_check_label = builder.get_object("error_check_label")
        self.invalid_entry = False
        # Advanced search window ****************************
        self.advanced_search_window = builder.get_object("advanced_search_window")
        self.advanced_search_filter = builder.get_object("advanced_filter")
        self.advanced_search_filter.set_visible_func(self.filter_the_data)
        self.advanced_search_sort = builder.get_object("advanced_sort")

        self.advanced_filter_entry = builder.get_object("advanced_filter_entry")
        self.advanced_search_treeview = builder.get_object("advanced_search_treeview")
        self.advanced_search = False

        # Login Items **************************************
        self.login_label = builder.get_object("Login_label")
        self.login_seuser_combobox = builder.get_object("login_seuser_combobox")
        self.login_seuser_combolist = builder.get_object("login_seuser_liststore")
        self.login_name_entry = builder.get_object("login_name_entry")
        self.login_mls_label = builder.get_object("login_mls_label")
        self.login_mls_entry = builder.get_object("login_mls_entry")
        self.login_radio_button = builder.get_object("Login_button")
        self.login_treeview = builder.get_object("login_treeview")
        self.login_liststore = builder.get_object("login_liststore")
        self.login_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.login_filter = builder.get_object("login_filter")
        self.login_filter.set_visible_func(self.filter_the_data)
        self.login_popup_window = builder.get_object("login_popup_window")
        self.login_delete_liststore = builder.get_object("login_delete_liststore")
        self.login_delete_window = builder.get_object("login_delete_window")

        # Users Items **************************************
        self.user_popup_window = builder.get_object("user_popup_window")
        self.user_radio_button = builder.get_object("User_button")
        self.user_liststore = builder.get_object("user_liststore")
        self.user_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.user_filter = builder.get_object("user_filter")
        self.user_filter.set_visible_func(self.filter_the_data)
        self.user_treeview = builder.get_object("user_treeview")
        self.user_roles_combobox = builder.get_object("user_roles_combobox")
        self.user_roles_combolist = builder.get_object("user_roles_liststore")
        self.user_label = builder.get_object("User_label")
        self.user_name_entry = builder.get_object("user_name_entry")
        self.user_mls_label = builder.get_object("user_mls_label")
        self.user_mls_level_entry = builder.get_object("user_mls_level_entry")
        self.user_mls_entry = builder.get_object("user_mls_entry")
        self.user_combobox = builder.get_object("selinux_user_combobox")
        self.user_delete_liststore = builder.get_object("user_delete_liststore")
        self.user_delete_window = builder.get_object("user_delete_window")

        # File Equiv Items **************************************
        self.file_equiv_label = builder.get_object("file_equiv_label")
        self.file_equiv_source_entry = builder.get_object("file_equiv_source_entry")
        self.file_equiv_dest_entry = builder.get_object("file_equiv_dest_entry")
        self.file_equiv_radio_button = builder.get_object("file_equiv_button")
        self.file_equiv_treeview = builder.get_object("file_equiv_treeview")
        self.file_equiv_liststore = builder.get_object("file_equiv_liststore")
        self.file_equiv_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.file_equiv_popup_window = builder.get_object("file_equiv_popup_window")
        self.file_equiv_treefilter = builder.get_object("file_equiv_filter")
        self.file_equiv_treefilter.set_visible_func(self.filter_the_data)
        self.file_equiv_delete_liststore = builder.get_object("file_equiv_delete_liststore")
        self.file_equiv_delete_window = builder.get_object("file_equiv_delete_window")

        # System Items **************************************
        self.app_system_button = builder.get_object("app_system_button")
        self.system_radio_button = builder.get_object("System_button")
        self.lockdown_radio_button = builder.get_object("Lockdown_button")
        self.systems_box = builder.get_object("Systems_box")
        self.relabel_button = builder.get_object("Relabel_button")
        self.relabel_button_no = builder.get_object("Relabel_button_no")
        self.advanced_system = builder.get_object("advanced_system")
        self.outer_notebook_frame = builder.get_object("outer_notebook_frame")
        self.system_policy_label = builder.get_object("system_policy_type_label")
        # Browse Items **************************************
        self.select_button_browse = builder.get_object("select_button_browse")
        self.cancel_button_browse = builder.get_object("cancel_button_browse")
        # More types window items ***************************
        self.moreTypes_window_files = builder.get_object("moreTypes_window_files")
        self.more_types_files_liststore = builder.get_object("more_types_file_liststore")
        self.moreTypes_treeview = builder.get_object("moreTypes_treeview_files")
        # System policy type ********************************
        self.system_policy_type_liststore = builder.get_object("system_policy_type_liststore")
        self.system_policy_type_combobox = builder.get_object("system_policy_type_combobox")
        self.policy_list = []
        if self.populate_system_policy() < 2:
            self.advanced_system.set_visible(False)
            self.system_policy_label.set_visible(False)
            self.system_policy_type_combobox.set_visible(False)

        self.enforcing_button_default = builder.get_object("Enforcing_button_default")
        self.permissive_button_default = builder.get_object("Permissive_button_default")
        self.disabled_button_default = builder.get_object("Disabled_button_default")
        self.initialize_system_default_mode()

        # Lockdown Window *********************************
        self.enable_unconfined_button = builder.get_object("enable_unconfined")
        self.disable_unconfined_button = builder.get_object("disable_unconfined")
        self.enable_permissive_button = builder.get_object("enable_permissive")
        self.disable_permissive_button = builder.get_object("disable_permissive")
        self.enable_ptrace_button = builder.get_object("enable_ptrace")
        self.disable_ptrace_button = builder.get_object("disable_ptrace")

        # Help Window *********************************
        self.help_window = builder.get_object("help_window")
        self.help_text = builder.get_object("help_textv")
        self.info_text = builder.get_object("info_text")
        self.help_image = builder.get_object("help_image")
        self.forward_button = builder.get_object("forward_button")
        self.back_button = builder.get_object("back_button")
        # Update menu items *********************************
        self.update_window = builder.get_object("update_window")
        self.update_treeview = builder.get_object("update_treeview")
        self.update_treestore = builder.get_object("Update_treestore")
        self.apply_button = builder.get_object("apply_button")
        self.update_button = builder.get_object("Update_button")
        # Add button objects ********************************
        self.add_button = builder.get_object("Add_button")
        self.delete_button = builder.get_object("Delete_button")

        self.files_path_entry = builder.get_object("files_path_entry")
        self.network_ports_entry = builder.get_object("network_ports_entry")
        self.files_popup_window = builder.get_object("files_popup_window")
        self.network_popup_window = builder.get_object("network_popup_window")

        self.popup_network_label = builder.get_object("Network_label")
        self.popup_files_label = builder.get_object("files_label")

        self.recursive_path_toggle = builder.get_object("make_path_recursive")
        self.files_type_combolist = builder.get_object("files_type_combo_store")
        self.files_class_combolist = builder.get_object("files_class_combo_store")
        self.files_type_combobox = builder.get_object("files_type_combobox")
        self.files_class_combobox = builder.get_object("files_class_combobox")
        self.files_mls_label = builder.get_object("files_mls_label")
        self.files_mls_entry = builder.get_object("files_mls_entry")
        self.advanced_text_files = builder.get_object("Advanced_text_files")
        self.files_cancel_button = builder.get_object("cancel_delete_files")

        self.network_tcp_button = builder.get_object("tcp_button")
        self.network_udp_button = builder.get_object("udp_button")
        self.network_port_type_combolist = builder.get_object("network_type_combo_store")
        self.network_port_type_combobox = builder.get_object("network_type_combobox")
        self.network_mls_label = builder.get_object("network_mls_label")
        self.network_mls_entry = builder.get_object("network_mls_entry")
        self.advanced_text_network = builder.get_object("Advanced_text_network")
        self.network_cancel_button = builder.get_object("cancel_network_delete")

        # Add button objects ********************************

        # Modify items **************************************
        self.show_mislabeled_files_only = builder.get_object("Show_mislabeled_files")
        self.mislabeled_files_label = builder.get_object("mislabeled_files_label")
        self.warning_files = builder.get_object("warning_files")
        self.modify_button = builder.get_object("Modify_button")
        self.modify_button.set_sensitive(False)
        # Modify items **************************************

        # Fix label *****************************************
        self.fix_label_window = builder.get_object("fix_label_window")
        self.fixlabel_label = builder.get_object("fixlabel_label")
        self.fix_label_cancel = builder.get_object("fix_label_cancel")
        # Fix label *****************************************

        # Delete items **************************************
        self.files_delete_window = builder.get_object("files_delete_window")
        self.files_delete_treeview = builder.get_object("files_delete_treeview")
        self.files_delete_liststore = builder.get_object("files_delete_liststore")
        self.network_delete_window = builder.get_object("network_delete_window")
        self.network_delete_treeview = builder.get_object("network_delete_treeview")
        self.network_delete_liststore = builder.get_object("network_delete_liststore")
        # Delete items **************************************

        # Progress bar **************************************
        self.progress_bar = builder.get_object("progress_bar")
        # Progress bar **************************************

        # executable_files items ****************************
        self.executable_files_treeview = builder.get_object("Executable_files_treeview")                  # Get the executable files tree view
        self.executable_files_filter = builder.get_object("executable_files_filter")
        self.executable_files_filter.set_visible_func(self.filter_the_data)
        self.executable_files_tab = builder.get_object("Executable_files_tab")
        self.executable_files_tab_tooltip_txt = self.executable_files_tab.get_tooltip_text()
        self.executable_files_liststore = builder.get_object("executable_files_treestore")
        self.executable_files_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)

        self.files_radio_button = builder.get_object("files_button")
        self.files_button_tooltip_txt = self.files_radio_button.get_tooltip_text()
        # executable_files items ****************************

        # writable files items ******************************
        self.writable_files_treeview = builder.get_object("Writable_files_treeview")           # Get the Writable files tree view
        self.writable_files_liststore = builder.get_object("writable_files_treestore")         # Contains the tree with File Path, SELinux File Label, Class
        self.writable_files_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.writable_files_filter = builder.get_object("writable_files_filter")
        self.writable_files_filter.set_visible_func(self.filter_the_data)
        self.writable_files_tab = builder.get_object("Writable_files_tab")
        self.writable_files_tab_tooltip_txt = self.writable_files_tab.get_tooltip_text()
        # writable files items ******************************

        # Application File Types ****************************
        self.application_files_treeview = builder.get_object("Application_files_treeview")                    # Get the Application files tree view
        self.application_files_filter = builder.get_object("application_files_filter")         # Contains the tree with File Path, Description, Class
        self.application_files_filter.set_visible_func(self.filter_the_data)
        self.application_files_tab = builder.get_object("Application_files_tab")
        self.application_files_tab_tooltip_txt = self.writable_files_tab.get_tooltip_text()
        self.application_files_liststore = builder.get_object("application_files_treestore")
        self.application_files_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.application_files_tab = builder.get_object("Application_files_tab")
        self.application_files_tab_tooltip_txt = self.application_files_tab.get_tooltip_text()
        # Application File Type *****************************

        # network items *************************************
        self.network_radio_button = builder.get_object("network_button")
        self.network_button_tooltip_txt = self.network_radio_button.get_tooltip_text()

        self.network_out_treeview = builder.get_object("outbound_treeview")
        self.network_out_liststore = builder.get_object("network_out_liststore")
        self.network_out_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.network_out_filter = builder.get_object("network_out_filter")
        self.network_out_filter.set_visible_func(self.filter_the_data)
        self.network_out_tab = builder.get_object("network_out_tab")
        self.network_out_tab_tooltip_txt = self.network_out_tab.get_tooltip_text()

        self.network_in_treeview = builder.get_object("inbound_treeview")
        self.network_in_liststore = builder.get_object("network_in_liststore")
        self.network_in_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.network_in_filter = builder.get_object("network_in_filter")
        self.network_in_filter.set_visible_func(self.filter_the_data)
        self.network_in_tab = builder.get_object("network_in_tab")
        self.network_in_tab_tooltip_txt = self.network_in_tab.get_tooltip_text()
        # network items *************************************

        # boolean items ************************************
        self.boolean_treeview = builder.get_object("Boolean_treeview")         # Get the booleans tree list
        self.boolean_liststore = builder.get_object("boolean_liststore")
        self.boolean_liststore.set_sort_column_id(2, Gtk.SortType.ASCENDING)
        self.boolean_filter = builder.get_object("boolean_filter")
        self.boolean_filter.set_visible_func(self.filter_the_data)

        self.boolean_more_detail_window = builder.get_object("booleans_more_detail_window")
        self.boolean_more_detail_treeview = builder.get_object("booleans_more_detail_treeview")
        self.boolean_more_detail_tree_data_set = builder.get_object("booleans_more_detail_liststore")
        self.boolean_radio_button = builder.get_object("Booleans_button")
        self.active_button = self.boolean_radio_button
        self.boolean_button_tooltip_txt = self.boolean_radio_button.get_tooltip_text()
        # boolean items ************************************

        # transitions items ************************************
        self.transitions_into_treeview = builder.get_object("transitions_into_treeview")         # Get the transitions tree list Enabled, source, Executable File
        self.transitions_into_liststore = builder.get_object("transitions_into_liststore")   # Contains the tree with
        self.transitions_into_liststore.set_sort_column_id(1, Gtk.SortType.ASCENDING)
        self.transitions_into_filter = builder.get_object("transitions_into_filter")
        self.transitions_into_filter.set_visible_func(self.filter_the_data)
        self.transitions_into_tab = builder.get_object("Transitions_into_tab")
        self.transitions_into_tab_tooltip_txt = self.transitions_into_tab.get_tooltip_text()

        self.transitions_radio_button = builder.get_object("Transitions_button")
        self.transitions_button_tooltip_txt = self.transitions_radio_button.get_tooltip_text()

        self.transitions_from_treeview = builder.get_object("transitions_from_treeview")         # Get the transitions tree list
        self.transitions_from_treestore = builder.get_object("transitions_from_treestore")       # Contains the tree with Enabled, Executable File Type, Transtype
        self.transitions_from_treestore.set_sort_column_id(2, Gtk.SortType.ASCENDING)
        self.transitions_from_filter = builder.get_object("transitions_from_filter")
        self.transitions_from_filter.set_visible_func(self.filter_the_data)
        self.transitions_from_tab = builder.get_object("Transitions_from_tab")
        self.transitions_from_tab_tooltip_txt = self.transitions_from_tab.get_tooltip_text()

        self.transitions_file_treeview = builder.get_object("file_transitions_treeview")         # Get the transitions tree list
        self.transitions_file_liststore = builder.get_object("file_transitions_liststore")       # Contains the tree with Enabled, Executable File Type, Transtype
        self.transitions_file_liststore.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.transitions_file_filter = builder.get_object("file_transitions_filter")
        self.transitions_file_filter.set_visible_func(self.filter_the_data)
        self.transitions_file_tab = builder.get_object("file_transitions")
        self.transitions_file_tab_tooltip_txt = self.transitions_from_tab.get_tooltip_text()
        # transitions items ************************************

        # Combobox and Entry items **************************
        self.combobox_menu = builder.get_object("combobox_org")                    # This is the combobox box object, aka the arrow next to the entry text bar
        self.application_liststore = builder.get_object("application_liststore")
        self.completion_entry = builder.get_object("completion_entry")  # self.combobox_menu.get_child()
        self.entrycompletion_obj = builder.get_object("entrycompletion_obj")
        #self.entrycompletion_obj = Gtk.EntryCompletion()
        self.entrycompletion_obj.set_minimum_key_length(0)
        self.entrycompletion_obj.set_text_column(0)
        self.entrycompletion_obj.set_match_func(self.match_func, None)
        self.completion_entry.set_completion(self.entrycompletion_obj)
        self.completion_entry.set_icon_from_stock(0, Gtk.STOCK_FIND)
        # Combobox and Entry items **************************

        # Modify buttons ************************************
        self.show_modified_only = builder.get_object("Show_modified_only_toggle")
        # Modify button *************************************

        # status bar *****************************************
        self.current_status_label = builder.get_object("Enforcing_label")
        self.current_status_enforcing = builder.get_object("Enforcing_button")
        self.current_status_permissive = builder.get_object("Permissive_button")
        self.status_bar = builder.get_object("status_bar")
        self.context_id = self.status_bar.get_context_id("SELinux status")

        # filters *********************************************
        self.filter_entry = builder.get_object("filter_entry")
        self.filter_box = builder.get_object("filter_box")
        self.add_modify_delete_box = builder.get_object("add_modify_delete_box")
        # Get_model() sets the tree model filter to be the parent of the tree model (tree model has all the data in it)

        # Toggle button ****************************************
        self.cell = builder.get_object("activate")
        self.del_cell_files = builder.get_object("files_toggle_delete")
        self.del_cell_files.connect("toggled", self.on_toggle_update, self.files_delete_liststore)
        self.del_cell_files_equiv = builder.get_object("file_equiv_toggle_delete1")
        self.del_cell_files_equiv.connect("toggled", self.on_toggle_update, self.file_equiv_delete_liststore)
        self.del_cell_user = builder.get_object("user_toggle_delete")
        self.del_cell_user.connect("toggled", self.on_toggle_update, self.user_delete_liststore)
        self.del_cell_login = builder.get_object("login_toggle_delete")
        self.del_cell_login.connect("toggled", self.on_toggle_update, self.login_delete_liststore)
        self.del_cell_network = builder.get_object("network_toggle_delete")
        self.del_cell_network.connect("toggled", self.on_toggle_update, self.network_delete_liststore)
        self.update_cell = builder.get_object("toggle_update")
        # Notebook items ***************************************
        self.outer_notebook = builder.get_object("outer_notebook")
        self.inner_notebook_files = builder.get_object("files_inner_notebook")
        self.inner_notebook_network = builder.get_object("network_inner_notebook")
        self.inner_notebook_transitions = builder.get_object("transitions_inner_notebook")
        # logind gui ***************************************
        loading_gui = builder.get_object("loading_gui")

        self.update_cell.connect("toggled", self.on_toggle_update, self.update_treestore)
        self.all_entries = []

        # Need to connect button on code because the tree view model is a treeviewsort
        self.cell.connect("toggled", self.on_toggle, self.boolean_liststore)

        self.loading = 1
        path = None
        if test:
            self.all_domains = ["httpd_t", "abrt_t"]
            if app and app not in self.all_domains:
                self.all_domains.append(app)
        else:
            self.all_domains = sepolicy.get_all_domains()
        self.all_domains.sort(key=str.lower)

        if app and app not in self.all_domains:
            self.error(_("%s is not a valid domain" % app))
            self.quit()

        loading_gui.show()
        length = len(self.all_domains)

        entrypoint_dict = sepolicy.get_init_entrypoints_str()
        for domain in self.all_domains:
            # After the user selects a path in the drop down menu call
            # get_init_entrypoint_target(entrypoint) to get the transtype
            # which will give you the application
            self.combo_box_add(domain, domain)
            self.percentage = float(float(self.loading) / float(length))
            self.progress_bar.set_fraction(self.percentage)
            self.progress_bar.set_pulse_step(self.percentage)
            self.idle_func()

            for entrypoint in entrypoint_dict.get(domain, []):
                path = sepolicy.find_entrypoint_path(entrypoint)
                if path:
                    self.combo_box_add(path, domain)
                    self.installed_list.append(path)

            self.loading += 1
        loading_gui.hide()
        self.entrycompletion_obj.set_model(self.application_liststore)
        self.advanced_search_treeview.set_model(self.advanced_search_sort)

        dic = {
            "on_combo_button_clicked": self.open_combo_menu,
            "on_disable_ptrace_toggled": self.on_disable_ptrace,
            "on_SELinux_window_configure_event": self.hide_combo_menu,
            "on_entrycompletion_obj_match_selected": self.set_application_label,
            "on_filter_changed": self.get_filter_data,
            "on_save_changes_file_equiv_clicked": self.update_to_file_equiv,
            "on_save_changes_login_clicked": self.update_to_login,
            "on_save_changes_user_clicked": self.update_to_user,
            "on_save_changes_files_clicked": self.update_to_files,
            "on_save_changes_network_clicked": self.update_to_network,
            "on_Advanced_text_files_button_press_event": self.reveal_advanced,
            "item_in_tree_selected": self.cursor_changed,
            "on_Application_file_types_treeview_configure_event": self.resize_wrap,
            "on_save_delete_clicked": self.on_save_delete_clicked,
            "on_moreTypes_treeview_files_row_activated": self.populate_type_combo,
            "on_retry_button_files_clicked": self.invalid_entry_retry,
            "on_make_path_recursive_toggled": self.recursive_path,
            "on_files_path_entry_button_press_event": self.highlight_entry_text,
            "on_files_path_entry_changed": self.autofill_add_files_entry,
            "on_select_type_files_clicked": self.select_type_more,
            "on_choose_file": self.on_browse_select,
            "on_Enforcing_button_toggled": self.set_enforce,
            "on_confirmation_close": self.confirmation_close,
            "on_column_clicked": self.column_clicked,
            "on_tab_switch": self.clear_filters,

            "on_file_equiv_button_clicked": self.show_file_equiv_page,
            "on_app/system_button_clicked": self.system_interface,
            "on_app/users_button_clicked": self.users_interface,
            "on_show_advanced_search_window": self.on_show_advanced_search_window,

            "on_Show_mislabeled_files_toggled": self.show_mislabeled_files,
            "on_Browse_button_files_clicked": self.browse_for_files,
            "on_cancel_popup_clicked": self.close_popup,
            "on_treeview_cursor_changed": self.cursor_changed,
            "on_login_seuser_combobox_changed": self.login_seuser_combobox_change,
            "on_user_roles_combobox_changed": self.user_roles_combobox_change,

            "on_cancel_button_browse_clicked": self.close_config_window,
            "on_apply_button_clicked": self.apply_changes_button_press,
            "on_Revert_button_clicked": self.update_or_revert_changes,
            "on_Update_button_clicked": self.update_or_revert_changes,
            "on_advanced_filter_entry_changed": self.get_advanced_filter_data,
            "on_advanced_search_treeview_row_activated": self.advanced_item_selected,
            "on_Select_advanced_search_clicked": self.advanced_item_button_push,
            "on_info_button_button_press_event": self.on_help_button,
            "on_back_button_clicked": self.on_help_back_clicked,
            "on_forward_button_clicked": self.on_help_forward_clicked,
            "on_Boolean_treeview_columns_changed": self.resize_columns,
            "on_completion_entry_changed": self.application_selected,
            "on_Add_button_clicked": self.add_button_clicked,
            "on_Delete_button_clicked": self.delete_button_clicked,
            "on_Modify_button_clicked": self.modify_button_clicked,
            "on_Show_modified_only_toggled": self.on_show_modified_only,
            "on_cancel_button_config_clicked": self.close_config_window,
            "on_Import_button_clicked": self.import_config_show,
            "on_Export_button_clicked": self.export_config_show,
            "on_enable_unconfined_toggled": self.unconfined_toggle,
            "on_enable_permissive_toggled": self.permissive_toggle,
            "on_system_policy_type_combobox_changed": self.change_default_policy,
            "on_Enforcing_button_default_toggled": self.change_default_mode,
            "on_Permissive_button_default_toggled": self.change_default_mode,
            "on_Disabled_button_default_toggled": self.change_default_mode,

            "on_Relabel_button_toggled_cb": self.relabel_on_reboot,
            "on_advanced_system_button_press_event": self.reveal_advanced_system,
            "on_files_type_combobox_changed": self.show_more_types,
            "on_filter_row_changed": self.filter_the_data,
            "on_button_toggled": self.tab_change,
            "gtk_main_quit": self.closewindow
        }

        self.previously_modified_initialize(customized)
        builder.connect_signals(dic)
        self.window.show()                # Show the gui to the screen
        GLib.timeout_add_seconds(5, self.selinux_status)
        self.selinux_status()
        self.lockdown_inited = False
        self.add_modify_delete_box.hide()
        self.filter_box.hide()
        if self.status == DISABLED:
            self.show_system_page()
        else:
            if self.application:
                self.applications_selection_button.set_label(self.application)
                self.completion_entry.set_text(self.application)
                self.show_applications_page()
                self.tab_change()
            else:
                self.clearbuttons()
                self.outer_notebook.set_current_page(START_PAGE)

        self.reinit()
        self.finish_init = True
        Gtk.main()

    def init_cur(self):
        self.cur_dict = {}
        for k in keys:
            self.cur_dict[k] = {}

    def remove_cur(self, ctr):
        i = 0
        for k in self.cur_dict:
            for j in self.cur_dict[k]:
                if i == ctr:
                    del(self.cur_dict[k][j])
                    return
                i += 1

    def selinux_status(self):
        try:
            self.status = selinux.security_getenforce()
        except OSError:
            self.status = DISABLED
        if self.status == DISABLED:
            self.current_status_label.set_sensitive(False)
            self.current_status_enforcing.set_sensitive(False)
            self.current_status_permissive.set_sensitive(False)
            self.enforcing_button_default.set_sensitive(False)
            self.status_bar.push(self.context_id, _("System Status: Disabled"))
            self.info_text.set_label(DISABLED_TEXT)
        else:
            self.set_enforce_text(self.status)
        if os.path.exists('/.autorelabel'):
            self.relabel_button.set_active(True)
        else:
            self.relabel_button_no.set_active(True)

        policytype = selinux.selinux_getpolicytype()[1]

        mode = selinux.selinux_getenforcemode()[1]
        if mode == ENFORCING:
            self.enforcing_button_default.set_active(True)
        if mode == PERMISSIVE:
            self.permissive_button_default.set_active(True)
        if mode == DISABLED:
            self.disabled_button_default.set_active(True)

        return True

    def lockdown_init(self):
        if self.lockdown_inited:
            return
        self.wait_mouse()
        self.lockdown_inited = True
        self.disable_ptrace_button.set_active(selinux.security_get_boolean_active("deny_ptrace"))
        self.module_dict = {}
        for m in self.dbus.semodule_list().split("\n"):
            mod = m.split()
            if len(mod) < 3:
                continue
            self.module_dict[mod[1]] = { "priority": mod[0], "Disabled" : (len(mod) > 3) }

        self.enable_unconfined_button.set_active(not self.module_dict["unconfined"]["Disabled"])
        self.enable_permissive_button.set_active(not self.module_dict["permissivedomains"]["Disabled"])
        self.ready_mouse()

    def column_clicked(self, treeview, treepath, treecol, *args):
        iter = self.get_selected_iter()
        if not iter:
            return

        if self.opage == BOOLEANS_PAGE:
            if treecol.get_name() == "more_detail_col":
                self.display_more_detail(self.window, treepath)

        if self.opage == FILES_PAGE:
            visible = self.liststore.get_value(iter, 3)
            # If visible is true then fix mislabeled will be visible
            if treecol.get_name() == "restorecon_col" and visible:
                self.fix_mislabeled(self.liststore.get_value(iter, 0))

        if self.opage == TRANSITIONS_PAGE:
            bool_name = self.liststore.get_value(iter, 1)
            if bool_name:
                self.boolean_radio_button.clicked()
                self.filter_entry.set_text(bool_name)

    def idle_func(self):
        while Gtk.events_pending():
            Gtk.main_iteration()

    def match_func(self, completion, key_string, iter, func_data):
        try:
            if self.application_liststore.get_value(iter, 0).find(key_string) != -1:
                return True
            return False
        except AttributeError:
            pass

    def help_show_page(self):
        self.back_button.set_sensitive(self.help_page != 0)
        self.forward_button.set_sensitive(self.help_page < (len(self.help_list) - 1))
        try:
            fd = open("%shelp/%s.txt" % (self.code_path, self.help_list[self.help_page]), "r")
            buf = fd.read()
            fd.close()
        except IOError:
            buf = ""
        help_text = self.help_text.get_buffer()
        help_text.set_text(buf % {"APP": self.application})
        self.help_text.set_buffer(help_text)
        self.help_image.set_from_file("%shelp/%s.png" % (self.code_path, self.help_list[self.help_page]))
        self.show_popup(self.help_window)

    def on_help_back_clicked(self, *args):
        self.help_page -= 1
        self.help_show_page()

    def on_help_forward_clicked(self, *args):
        self.help_page += 1
        self.help_show_page()

    def on_help_button(self, *args):
        self.help_page = 0
        self.help_list = []
        if self.opage == START_PAGE:
            self.help_window.set_title(_("Help: Start Page"))
            self.help_list = ["start"]

        if self.opage == BOOLEANS_PAGE:
            self.help_window.set_title(_("Help: Booleans Page"))
            self.help_list = ["booleans", "booleans_toggled", "booleans_more", "booleans_more_show"]

        if self.opage == FILES_PAGE:
            ipage = self.inner_notebook_files.get_current_page()
            if ipage == EXE_PAGE:
                self.help_window.set_title(_("Help: Executable Files Page"))
                self.help_list = ["files_exec"]
            if ipage == WRITABLE_PAGE:
                self.help_window.set_title(_("Help: Writable Files Page"))
                self.help_list = ["files_write"]
            if ipage == APP_PAGE:
                self.help_window.set_title(_("Help: Application Types Page"))
                self.help_list = ["files_app"]
        if self.opage == NETWORK_PAGE:
            ipage = self.inner_notebook_network.get_current_page()
            if ipage == OUTBOUND_PAGE:
                self.help_window.set_title(_("Help: Outbound Network Connections Page"))
                self.help_list = ["ports_outbound"]
            if ipage == INBOUND_PAGE:
                self.help_window.set_title(_("Help: Inbound Network Connections Page"))
                self.help_list = ["ports_inbound"]

        if self.opage == TRANSITIONS_PAGE:
            ipage = self.inner_notebook_transitions.get_current_page()
            if ipage == TRANSITIONS_FROM_PAGE:
                self.help_window.set_title(_("Help: Transition from application Page"))
                self.help_list = ["transition_from", "transition_from_boolean", "transition_from_boolean_1", "transition_from_boolean_2"]
            if ipage == TRANSITIONS_TO_PAGE:
                self.help_window.set_title(_("Help: Transition into application Page"))
                self.help_list = ["transition_to"]
            if ipage == TRANSITIONS_FILE_PAGE:
                self.help_window.set_title(_("Help: Transition application file Page"))
                self.help_list = ["transition_file"]

        if self.opage == SYSTEM_PAGE:
            self.help_window.set_title(_("Help: Systems Page"))
            self.help_list = ["system", "system_boot_mode", "system_current_mode", "system_export", "system_policy_type", "system_relabel"]

        if self.opage == LOCKDOWN_PAGE:
            self.help_window.set_title(_("Help: Lockdown Page"))
            self.help_list = ["lockdown", "lockdown_unconfined", "lockdown_permissive", "lockdown_ptrace"]

        if self.opage == LOGIN_PAGE:
            self.help_window.set_title(_("Help: Login Page"))
            self.help_list = ["login", "login_default"]

        if self.opage == USER_PAGE:
            self.help_window.set_title(_("Help: SELinux User Page"))
            self.help_list = ["users"]

        if self.opage == FILE_EQUIV_PAGE:
            self.help_window.set_title(_("Help: File Equivalence Page"))
            self.help_list = ["file_equiv"]
        return self.help_show_page()

    def open_combo_menu(self, *args):
        if self.popup == 0:
            self.popup = 1
            location = self.window.get_position()
            self.main_selection_window.move(location[0] + 2, location[1] + 65)
            self.main_selection_window.show()
        else:
            self.main_selection_window.hide()
            self.popup = 0

    def hide_combo_menu(self, *args):
        self.main_selection_window.hide()
        self.popup = 0

    def set_application_label(self, *args):
        self.set_application_label = True

    def resize_wrap(self, *args):
        print(args)

    def initialize_system_default_mode(self):
        self.enforce_mode = selinux.selinux_getenforcemode()[1]
        if self.enforce_mode == ENFORCING:
            self.enforce_button = self.enforcing_button_default
        if self.enforce_mode == PERMISSIVE:
            self.enforce_button = self.permissive_button_default
        if self.enforce_mode == DISABLED:
            self.enforce_button = self.disabled_button_default

    def populate_system_policy(self):
        types = next(os.walk(selinux.selinux_path(), topdown=True))[1]
        types.sort()
        ctr = 0
        for item in types:
            iter = self.system_policy_type_liststore.append()
            self.system_policy_type_liststore.set_value(iter, 0, item)
            if item == self.initialtype:
                self.system_policy_type_combobox.set_active(ctr)
                self.typeHistory = ctr
            ctr += 1
        return ctr

    def filter_the_data(self, list, iter, *args):
        # When there is no txt in the box show all items in the tree
        if self.filter_txt == "":
            return True
        try:
            for x in range(0, list.get_n_columns()):
                try:
                    val = list.get_value(iter, x)
                    if val is True or val is False or val is None:
                        continue
                    # Returns true if filter_txt exists within the val
                    if(val.find(self.filter_txt) != -1 or val.lower().find(self.filter_txt) != -1):
                        return True
                except (AttributeError, TypeError):
                    pass
        except:  # ValueError:
            pass
        return False

    def net_update(self, app, netd, protocol, direction, model):
        for k in netd.keys():
            for t, ports in netd[k]:
                pkey = (",".join(ports), protocol)
                if pkey in self.cur_dict["port"]:
                    if self.cur_dict["port"][pkey]["action"] == "-d":
                        continue
                    if t != self.cur_dict["port"][pkey]["type"]:
                        continue
                self.network_initial_data_insert(model, ", ".join(ports), t, protocol)

    def file_equiv_initialize(self):
        self.wait_mouse()
        edict = sepolicy.get_file_equiv()
        self.file_equiv_liststore.clear()
        for f in edict:
            iter = self.file_equiv_liststore.append()
            if edict[f]["modify"]:
                name = self.markup(f)
                equiv = self.markup(edict[f]["equiv"])
            else:
                name = f
                equiv = edict[f]["equiv"]

            self.file_equiv_liststore.set_value(iter, 0, name)
            self.file_equiv_liststore.set_value(iter, 1, equiv)
            self.file_equiv_liststore.set_value(iter, 2, edict[f]["modify"])
        self.ready_mouse()

    def user_initialize(self):
        self.wait_mouse()
        self.user_liststore.clear()
        for u in sepolicy.get_selinux_users():
            iter = self.user_liststore.append()
            self.user_liststore.set_value(iter, 0, str(u["name"]))
            roles = u["roles"]
            if "object_r" in roles:
                roles.remove("object_r")
            self.user_liststore.set_value(iter, 1, ", ".join(roles))
            self.user_liststore.set_value(iter, 2, u.get("level", ""))
            self.user_liststore.set_value(iter, 3, u.get("range", ""))
            self.user_liststore.set_value(iter, 4, True)
        self.ready_mouse()

    def login_initialize(self):
        self.wait_mouse()
        self.login_liststore.clear()
        for u in sepolicy.get_login_mappings():
            iter = self.login_liststore.append()
            self.login_liststore.set_value(iter, 0, u["name"])
            self.login_liststore.set_value(iter, 1, u["seuser"])
            self.login_liststore.set_value(iter, 2, u["mls"])
            self.login_liststore.set_value(iter, 3, True)
        self.ready_mouse()

    def network_initialize(self, app):
        netd = sepolicy.network.get_network_connect(app, "tcp", "name_connect", check_bools=True)
        self.net_update(app, netd, "tcp", OUTBOUND_PAGE, self.network_out_liststore)
        netd = sepolicy.network.get_network_connect(app, "tcp", "name_bind", check_bools=True)
        self.net_update(app, netd, "tcp", INBOUND_PAGE, self.network_in_liststore)
        netd = sepolicy.network.get_network_connect(app, "udp", "name_bind", check_bools=True)
        self.net_update(app, netd, "udp", INBOUND_PAGE, self.network_in_liststore)

    def network_initial_data_insert(self, model, ports, portType, protocol):
        iter = model.append()
        model.set_value(iter, 0, ports)
        model.set_value(iter, 1, protocol)
        model.set_value(iter, 2, portType)
        model.set_value(iter, 4, True)

    def combo_set_active_text(self, combobox, val):
        ctr = 0
        liststore = combobox.get_model()
        for i in liststore:
            if i[0] == val:
                combobox.set_active(ctr)
                return
            ctr += 1

        niter = liststore.get_iter(ctr - 1)
        if liststore.get_value(niter, 0) == _("More..."):
            iter = liststore.insert_before(niter)
            ctr = ctr - 1
        else:
            iter = liststore.append()
        liststore.set_value(iter, 0, val)
        combobox.set_active(ctr)

    def combo_get_active_text(self, combobox):
        liststore = combobox.get_model()
        index = combobox.get_active()
        if index < 0:
            return None
        iter = liststore.get_iter(index)
        return liststore.get_value(iter, 0)

    def combo_box_add(self, val, val1):
        if val is None:
            return
        iter = self.application_liststore.append()
        self.application_liststore.set_value(iter, 0, val)
        self.application_liststore.set_value(iter, 1, val1)

    def select_type_more(self, *args):
        app = self.moreTypes_treeview.get_selection()
        iter = app.get_selected()[1]
        if iter is None:
            return
        app = self.more_types_files_liststore.get_value(iter, 0)
        self.combo_set_active_text(self.files_type_combobox, app)
        self.closewindow(self.moreTypes_window_files)

    def advanced_item_button_push(self, *args):
        row = self.advanced_search_treeview.get_selection()
        model, iter = row.get_selected()
        iter = model.convert_iter_to_child_iter(iter)
        iter = self.advanced_search_filter.convert_iter_to_child_iter(iter)
        app = self.application_liststore.get_value(iter, 1)
        if app is None:
            return
        self.advanced_filter_entry.set_text('')
        self.advanced_search_window.hide()
        self.reveal_advanced(self.main_advanced_label)
        self.completion_entry.set_text(app)

    def advanced_item_selected(self, treeview, path, *args):
        iter = self.advanced_search_filter.get_iter(path)
        iter = self.advanced_search_filter.convert_iter_to_child_iter(iter)
        app = self.application_liststore.get_value(iter, 1)
        self.advanced_filter_entry.set_text('')
        self.advanced_search_window.hide()
        self.reveal_advanced(self.main_advanced_label)
        self.completion_entry.set_text(app)
        self.application_selected()

    def find_application(self, app):
        if app and len(app) > 0:
            for items in self.application_liststore:
                if app == items[0]:
                    return True
        return False

    def application_selected(self, *args):
        self.show_mislabeled_files_only.set_visible(False)
        self.mislabeled_files_label.set_visible(False)
        self.warning_files.set_visible(False)
        self.filter_entry.set_text('')

        app = self.completion_entry.get_text()
        if not self.find_application(app):
            return
        self.show_applications_page()
        self.add_button.set_sensitive(True)
        self.delete_button.set_sensitive(True)
        # Clear the tree to prepare for a new selection otherwise
        self.executable_files_liststore.clear()
        # data will pile up everytime the user selects a new item from the drop down menu
        self.network_in_liststore.clear()
        self.network_out_liststore.clear()
        self.boolean_liststore.clear()
        self.transitions_into_liststore.clear()
        self.transitions_from_treestore.clear()
        self.application_files_liststore.clear()
        self.writable_files_liststore.clear()
        self.transitions_file_liststore.clear()

        try:
            if app[0] == '/':
                app = sepolicy.get_init_transtype(app)
                if not app:
                    return
                self.application = app
        except IndexError:
            pass

        self.wait_mouse()
        self.previously_modified_initialize(self.dbus.customized())
        self.reinit()
        self.boolean_initialize(app)
        self.mislabeled_files = False
        self.executable_files_initialize(app)
        self.network_initialize(app)
        self.writable_files_initialize(app)
        self.transitions_into_initialize(app)
        self.transitions_from_initialize(app)
        self.application_files_initialize(app)
        self.transitions_files_initialize(app)

        self.executable_files_tab.set_tooltip_text(_("File path used to enter the '%s' domain." % app))
        self.writable_files_tab.set_tooltip_text(_("Files to which the '%s' domain can write." % app))
        self.network_out_tab.set_tooltip_text(_("Network Ports to which the '%s' is allowed to connect." % app))
        self.network_in_tab.set_tooltip_text(_("Network Ports to which the '%s' is allowed to listen." % app))
        self.application_files_tab.set_tooltip_text(_("File Types defined for the '%s'." % app))
        self.boolean_radio_button.set_tooltip_text(_("Display boolean information that can be used to modify the policy for the '%s'." % app))
        self.files_radio_button.set_tooltip_text(_("Display file type information that can be used by the '%s'." % app))
        self.network_radio_button.set_tooltip_text(_("Display network ports to which the '%s' can connect or listen to." % app))
        self.transitions_into_tab.set_label(_("Application Transitions Into '%s'" % app))
        self.transitions_from_tab.set_label(_("Application Transitions From '%s'" % app))
        self.transitions_file_tab.set_label(_("File Transitions From '%s'" % app))
        self.transitions_into_tab.set_tooltip_text(_("Executables which will transition to '%s', when executing selected domains entrypoint.") % app)
        self.transitions_from_tab.set_tooltip_text(_("Executables which will transition to a different domain, when '%s' executes them.") % app)
        self.transitions_file_tab.set_tooltip_text(_("Files by '%s' with transitions to a different label." % app))
        self.transitions_radio_button.set_tooltip_text(_("Display applications that can transition into or out of the '%s'." % app))

        self.application = app
        self.applications_selection_button.set_label(self.application)
        self.ready_mouse()

    def reinit(self):
        sepolicy.reinit()
        self.fcdict = sepolicy.get_fcdict()
        self.local_file_paths = sepolicy.get_local_file_paths()

    def previously_modified_initialize(self, buf):
        self.cust_dict = {}
        for i in buf.split("\n"):
            rec = i.split()
            if len(rec) == 0:
                continue
            if rec[1] == "-D":
                continue
            if rec[0] not in self.cust_dict:
                self.cust_dict[rec[0]] = {}
            if rec[0] == "boolean":
                self.cust_dict["boolean"][rec[-1]] = {"active": rec[2] == "-1"}
            if rec[0] == "login":
                self.cust_dict["login"][rec[-1]] = {"seuser": rec[3], "range": rec[5]}
            if rec[0] == "interface":
                self.cust_dict["interface"][rec[-1]] = {"type": rec[3]}
            if rec[0] == "user":
                self.cust_dict["user"][rec[-1]] = {"level": "s0", "range": rec[3], "role": rec[5]}
            if rec[0] == "port":
                self.cust_dict["port"][(rec[-1], rec[-2])] = {"type": rec[3]}
            if rec[0] == "node":
                self.cust_dict["node"][rec[-1]] = {"mask": rec[3], "protocol": rec[5], "type": rec[7]}
            if rec[0] == "fcontext":
                if rec[2] == "-e":
                    if "fcontext-equiv" not in self.cust_dict:
                        self.cust_dict["fcontext-equiv"] = {}
                    self.cust_dict["fcontext-equiv"][(rec[-1])] = {"equiv": rec[3]}
                else:
                    self.cust_dict["fcontext"][(rec[-1], rec[3])] = {"type": rec[5]}
            if rec[0] == "module":
                self.cust_dict["module"][rec[-1]] = {"enabled": rec[2] != "-d"}

        if "module" not in self.cust_dict:
            return
        for semodule, button in [("unconfined", self.disable_unconfined_button), ("permissivedomains", self.disable_permissive_button)]:
            if semodule in self.cust_dict["module"]:
                button.set_active(self.cust_dict["module"][semodule]["enabled"])

        for i in keys:
            if i not in self.cust_dict:
                self.cust_dict.update({i: {}})

    def executable_files_initialize(self, application):
        self.entrypoints = sepolicy.get_entrypoints(application)
        for exe in self.entrypoints.keys():
            if len(self.entrypoints[exe]) == 0:
                continue
            file_class = self.entrypoints[exe][1]
            for path in self.entrypoints[exe][0]:
                if (path, file_class) in self.cur_dict["fcontext"]:
                    if self.cur_dict["fcontext"][(path, file_class)]["action"] == "-d":
                        continue
                    if exe != self.cur_dict["fcontext"][(path, file_class)]["type"]:
                        continue
                self.files_initial_data_insert(self.executable_files_liststore, path, exe, file_class)

    def mislabeled(self, path):
        try:
            con = selinux.matchpathcon(path, 0)[1]
            cur = selinux.getfilecon(path)[1]
            return con != cur
        except OSError:
            return False

    def set_mislabeled(self, tree, path, iter, niter):
        if not self.mislabeled(path):
            return
        con = selinux.matchpathcon(path, 0)[1]
        cur = selinux.getfilecon(path)[1]
        self.mislabeled_files = True
        # Set visibility of label
        tree.set_value(niter, 3, True)
        # Has a mislabel
        tree.set_value(iter, 4, True)
        tree.set_value(niter, 4, True)
        tree.set_value(iter, 5, con.split(":")[2])
        tree.set_value(iter, 6, cur.split(":")[2])

    def writable_files_initialize(self, application):
        # Traversing the dictionary data struct
        self.writable_files = sepolicy.get_writable_files(application)
        for write in self.writable_files.keys():
            if len(self.writable_files[write]) < 2:
                self.files_initial_data_insert(self.writable_files_liststore, None, write, _("all files"))
                continue
            file_class = self.writable_files[write][1]
            for path in self.writable_files[write][0]:
                if (path, file_class) in self.cur_dict["fcontext"]:
                    if self.cur_dict["fcontext"][(path, file_class)]["action"] == "-d":
                        continue
                    if write != self.cur_dict["fcontext"][(path, file_class)]["type"]:
                        continue
                self.files_initial_data_insert(self.writable_files_liststore, path, write, file_class)

    def files_initial_data_insert(self, liststore, path, seLinux_label, file_class):
        iter = liststore.append(None)
        if path is None:
            path = _("MISSING FILE PATH")
            modify = False
        else:
            modify = (path, file_class) in self.local_file_paths
            for p in sepolicy.find_file(path):
                niter = liststore.append(iter)
                liststore.set_value(niter, 0, p)
                self.set_mislabeled(liststore, p, iter, niter)
            if modify:
                path = self.markup(path)
                file_class = self.markup(selinux_label)
                file_class = self.markup(file_class)
        liststore.set_value(iter, 0, path)
        liststore.set_value(iter, 1, seLinux_label)
        liststore.set_value(iter, 2, file_class)
        liststore.set_value(iter, 7, modify)

    def markup(self, f):
        return "<b>%s</b>" % f

    def unmarkup(self, f):
        if f:
            return re.sub("</b>$", "", re.sub("^<b>", "", f))
        return None

    def application_files_initialize(self, application):
        self.file_types = sepolicy.get_file_types(application)
        for app in self.file_types.keys():
            if len(self.file_types[app]) == 0:
                continue
            file_class = self.file_types[app][1]
            for path in self.file_types[app][0]:
                desc = sepolicy.get_description(app, markup=self.markup)
                if (path, file_class) in self.cur_dict["fcontext"]:
                    if self.cur_dict["fcontext"][(path, file_class)]["action"] == "-d":
                        continue
                    if app != self.cur_dict["fcontext"][(path, file_class)]["type"]:
                        continue
                self.files_initial_data_insert(self.application_files_liststore, path, desc, file_class)

    def modified(self):
        i = 0
        for k in self.cur_dict:
            if len(self.cur_dict[k]) > 0:
                return True
        return False

    def boolean_initialize(self, application):
        for blist in sepolicy.get_bools(application):
            for b, active in blist:
                if b in self.cur_dict["boolean"]:
                    active = self.cur_dict["boolean"][b]['active']
                desc = sepolicy.boolean_desc(b)
                self.boolean_initial_data_insert(b, desc, active)

    def boolean_initial_data_insert(self, val, desc, active):
        # Insert data from data source into tree
        iter = self.boolean_liststore.append()
        self.boolean_liststore.set_value(iter, 0, active)
        self.boolean_liststore.set_value(iter, 1, desc)
        self.boolean_liststore.set_value(iter, 2, val)
        self.boolean_liststore.set_value(iter, 3, _('More...'))

    def transitions_into_initialize(self, application):
        for x in sepolicy.get_transitions_into(application):
            active = None
            executable = None
            source = None
            if "boolean" in x:
                active = x["boolean"]
            if "target" in x:
                executable = x["target"]
            if "source" in x:
                source = x["source"]
            self.transitions_into_initial_data_insert(active, executable, source)

    def transitions_into_initial_data_insert(self, active, executable, source):
        iter = self.transitions_into_liststore.append()
        if active != None:
            self.transitions_into_liststore.set_value(iter, 0, enabled[active[0][1]])         # active[0][1] is either T or F (enabled is all the way at the top)
        else:
            self.transitions_into_liststore.set_value(iter, 0, "Default")

        self.transitions_into_liststore.set_value(iter, 2, executable)
        self.transitions_into_liststore.set_value(iter, 1, source)

    def transitions_from_initialize(self, application):
        for x in sepolicy.get_transitions(application):
            active = None
            executable = None
            transtype = None
            if "boolean" in x:
                active = x["boolean"]
            if "target" in x:
                executable_type = x["target"]
            if "transtype" in x:
                transtype = x["transtype"]
            self.transitions_from_initial_data_insert(active, executable_type, transtype)
            try:
                for executable in self.fcdict[executable_type]["regex"]:
                    self.transitions_from_initial_data_insert(active, executable, transtype)
            except KeyError:
                pass

    def transitions_from_initial_data_insert(self, active, executable, transtype):
        iter = self.transitions_from_treestore.append(None)
        if active == None:
            self.transitions_from_treestore.set_value(iter, 0, "Default")
            self.transitions_from_treestore.set_value(iter, 5, False)
        else:
            niter = self.transitions_from_treestore.append(iter)
            # active[0][1] is either T or F (enabled is all the way at the top)
            self.transitions_from_treestore.set_value(iter, 0, enabled[active[0][1]])
            markup = ('<span foreground="blue"><u>','</u></span>')
            if active[0][1]:
                self.transitions_from_treestore.set_value(niter, 2, (_("To disable this transition, go to the %sBoolean section%s.") % markup))
            else:
                self.transitions_from_treestore.set_value(niter, 2, (_("To enable this transition, go to the %sBoolean section%s.") % markup))

            # active[0][0] is the Bool Name
            self.transitions_from_treestore.set_value(niter, 1, active[0][0])
            self.transitions_from_treestore.set_value(niter, 5, True)

        self.transitions_from_treestore.set_value(iter, 2, executable)
        self.transitions_from_treestore.set_value(iter, 3, transtype)

    def transitions_files_initialize(self, application):
        for i in sepolicy.get_file_transitions(application):
            if 'filename' in i:
                filename = i['filename']
            else:
                filename = None
            self.transitions_files_inital_data_insert(i['target'], i['class'], i['transtype'], filename)

    def transitions_files_inital_data_insert(self, path, tclass, dest, name):
        iter = self.transitions_file_liststore.append()
        self.transitions_file_liststore.set_value(iter, 0, path)
        self.transitions_file_liststore.set_value(iter, 1, tclass)
        self.transitions_file_liststore.set_value(iter, 2, dest)
        if name == None:
            name = '*'
        self.transitions_file_liststore.set_value(iter, 3, name)

    def tab_change(self, *args):
        self.clear_filters()
        self.treeview = None
        self.treesort = None
        self.treefilter = None
        self.liststore = None
        self.modify_button.set_sensitive(False)
        self.add_modify_delete_box.hide()
        self.show_modified_only.set_visible(False)
        self.show_mislabeled_files_only.set_visible(False)
        self.mislabeled_files_label.set_visible(False)
        self.warning_files.set_visible(False)

        if self.boolean_radio_button.get_active():
            self.outer_notebook.set_current_page(BOOLEANS_PAGE)
            self.treeview = self.boolean_treeview
            self.show_modified_only.set_visible(True)

        if self.files_radio_button.get_active():
            self.show_popup(self.add_modify_delete_box)
            self.show_modified_only.set_visible(True)
            self.show_mislabeled_files_only.set_visible(self.mislabeled_files)
            self.mislabeled_files_label.set_visible(self.mislabeled_files)
            self.warning_files.set_visible(self.mislabeled_files)
            self.outer_notebook.set_current_page(FILES_PAGE)
            if args[0] == self.inner_notebook_files:
                ipage = args[2]
            else:
                ipage = self.inner_notebook_files.get_current_page()
            if ipage == EXE_PAGE:
                self.treeview = self.executable_files_treeview
                category = _("executable")
            elif ipage == WRITABLE_PAGE:
                self.treeview = self.writable_files_treeview
                category = _("writable")
            elif ipage == APP_PAGE:
                self.treeview = self.application_files_treeview
                category = _("application")
            self.add_button.set_tooltip_text(_("Add new %(TYPE)s file path for '%(DOMAIN)s' domains.") % {"TYPE": category, "DOMAIN": self.application})
            self.delete_button.set_tooltip_text(_("Delete %(TYPE)s file paths for '%(DOMAIN)s' domain.") % {"TYPE": category, "DOMAIN": self.application})
            self.modify_button.set_tooltip_text(_("Modify %(TYPE)s file path for '%(DOMAIN)s' domain. Only bolded items in the list can be selected, this indicates they were modified previously.") % {"TYPE": category, "DOMAIN": self.application})

        if self.network_radio_button.get_active():
            self.add_modify_delete_box.show()
            self.show_modified_only.set_visible(True)
            self.outer_notebook.set_current_page(NETWORK_PAGE)
            if args[0] == self.inner_notebook_network:
                ipage = args[2]
            else:
                ipage = self.inner_notebook_network.get_current_page()
            if ipage == OUTBOUND_PAGE:
                self.treeview = self.network_out_treeview
                category = _("connect")
            if ipage == INBOUND_PAGE:
                self.treeview = self.network_in_treeview
                category = _("listen for inbound connections")

            self.add_button.set_tooltip_text(_("Add new port definition to which the '%(APP)s' domain is allowed to %(PERM)s.") % {"APP": self.application, "PERM": category})
            self.delete_button.set_tooltip_text(_("Delete modified port definitions to which the '%(APP)s' domain is allowed to %(PERM)s.") % {"APP": self.application, "PERM": category})
            self.modify_button.set_tooltip_text(_("Modify port definitions to which the '%(APP)s' domain is allowed to %(PERM)s.") % {"APP": self.application, "PERM": category})

        if self.transitions_radio_button.get_active():
            self.outer_notebook.set_current_page(TRANSITIONS_PAGE)
            if args[0] == self.inner_notebook_transitions:
                ipage = args[2]
            else:
                ipage = self.inner_notebook_transitions.get_current_page()
            if ipage == TRANSITIONS_FROM_PAGE:
                self.treeview = self.transitions_from_treeview
            if ipage == TRANSITIONS_TO_PAGE:
                self.treeview = self.transitions_into_treeview
            if ipage == TRANSITIONS_FILE_PAGE:
                self.treeview = self.transitions_file_treeview

        if self.system_radio_button.get_active():
            self.outer_notebook.set_current_page(SYSTEM_PAGE)
            self.filter_box.hide()

        if self.lockdown_radio_button.get_active():
            self.lockdown_init()
            self.outer_notebook.set_current_page(LOCKDOWN_PAGE)
            self.filter_box.hide()

        if self.user_radio_button.get_active():
            self.outer_notebook.set_current_page(USER_PAGE)
            self.add_modify_delete_box.show()
            self.show_modified_only.set_visible(True)
            self.treeview = self.user_treeview
            self.add_button.set_tooltip_text(_("Add new SELinux User/Role definition."))
            self.delete_button.set_tooltip_text(_("Delete modified SELinux User/Role definitions."))
            self.modify_button.set_tooltip_text(_("Modify selected modified SELinux User/Role definitions."))

        if self.login_radio_button.get_active():
            self.outer_notebook.set_current_page(LOGIN_PAGE)
            self.add_modify_delete_box.show()
            self.show_modified_only.set_visible(True)
            self.treeview = self.login_treeview
            self.add_button.set_tooltip_text(_("Add new Login Mapping definition."))
            self.delete_button.set_tooltip_text(_("Delete modified Login Mapping definitions."))
            self.modify_button.set_tooltip_text(_("Modify selected modified Login Mapping definitions."))

        if self.file_equiv_radio_button.get_active():
            self.outer_notebook.set_current_page(FILE_EQUIV_PAGE)
            self.add_modify_delete_box.show()
            self.show_modified_only.set_visible(True)
            self.treeview = self.file_equiv_treeview
            self.add_button.set_tooltip_text(_("Add new File Equivalence definition."))
            self.delete_button.set_tooltip_text(_("Delete modified File Equivalence definitions."))
            self.modify_button.set_tooltip_text(_("Modify selected modified File Equivalence definitions. Only bolded items in the list can be selected, this indicates they were modified previously."))

        self.opage = self.outer_notebook.get_current_page()
        if self.treeview:
            self.filter_box.show()
            self.treesort = self.treeview.get_model()
            self.treefilter = self.treesort.get_model()
            self.liststore = self.treefilter.get_model()
            for x in range(0, self.liststore.get_n_columns()):
                col = self.treeview.get_column(x)
                if col:
                    cell = col.get_cells()[0]
                    if isinstance(cell, Gtk.CellRendererText):
                        self.liststore.set_sort_func(x, self.stripsort, None)
            self.treeview.get_selection().unselect_all()
        self.modify_button.set_sensitive(False)

    def stripsort(self, model, row1, row2, user_data):
        sort_column, _ = model.get_sort_column_id()
        val1 = self.unmarkup(model.get_value(row1, sort_column))
        val2 = self.unmarkup(model.get_value(row2, sort_column))
        return cmp(val1, val2)

    def display_more_detail(self, windows, path):
        it = self.boolean_filter.get_iter(path)
        it = self.boolean_filter.convert_iter_to_child_iter(it)

        self.boolean_more_detail_tree_data_set.clear()
        self.boolean_more_detail_window.set_title(_("Boolean %s Allow Rules") % self.boolean_liststore.get_value(it, 2))
        blist = sepolicy.get_boolean_rules(self.application, self.boolean_liststore.get_value(it, 2))
        for b in blist:
            self.display_more_detail_init(b["source"], b["target"], b["class"], b["permlist"])
        self.show_popup(self.boolean_more_detail_window)

    def display_more_detail_init(self, source, target, class_type, permission):
        iter = self.boolean_more_detail_tree_data_set.append()
        self.boolean_more_detail_tree_data_set.set_value(iter, 0, "allow %s %s:%s { %s };" % (source, target, class_type, " ".join(permission)))

    def add_button_clicked(self, *args):
        self.modify = False
        if self.opage == NETWORK_PAGE:
            self.popup_network_label.set_text((_("Add Network Port for %s.  Ports will be created when update is applied.")) % self.application)
            self.network_popup_window.set_title((_("Add Network Port for %s")) % self.application)
            self.init_network_dialog(args)
            return

        if self.opage == FILES_PAGE:
            self.popup_files_label.set_text((_("Add File Labeling for %s. File labels will be created when update is applied.")) % self.application)
            self.files_popup_window.set_title((_("Add File Labeling for %s")) % self.application)
            self.init_files_dialog(args)
            ipage = self.inner_notebook_files.get_current_page()
            if ipage == EXE_PAGE:
                self.files_path_entry.set_text("ex: /usr/sbin/Foobar")
            else:
                self.files_path_entry.set_text("ex: /var/lib/Foobar")
            self.clear_entry = True

        if self.opage == LOGIN_PAGE:
            self.login_label.set_text((_("Add Login Mapping. User Mapping will be created when Update is applied.")))
            self.login_popup_window.set_title(_("Add Login Mapping"))
            self.login_init_dialog(args)
            self.clear_entry = True

        if self.opage == USER_PAGE:
            self.user_label.set_text((_("Add SELinux User Role. SELinux user roles will be created when update is applied.")))
            self.user_popup_window.set_title(_("Add SELinux Users"))
            self.user_init_dialog(args)
            self.clear_entry = True

        if self.opage == FILE_EQUIV_PAGE:
            self.file_equiv_source_entry.set_text("")
            self.file_equiv_dest_entry.set_text("")
            self.file_equiv_label.set_text((_("Add File Equivalency Mapping. Mapping will be created when update is applied.")))
            self.file_equiv_popup_window.set_title(_("Add SELinux File Equivalency"))
            self.clear_entry = True
            self.show_popup(self.file_equiv_popup_window)

        self.new_updates()

    def show_popup(self, window):
        self.current_popup = window
        window.show()

    def close_popup(self, *args):
        self.current_popup.hide()
        self.window.set_sensitive(True)
        return True

    def modify_button_clicked(self, *args):
        iter = None
        if self.treeview:
            iter = self.get_selected_iter()
            if not iter:
                self.modify_button.set_sensitive(False)
                return
        self.modify = True
        if self.opage == NETWORK_PAGE:
            self.modify_button_network_clicked(args)

        if self.opage == FILES_PAGE:
            self.popup_files_label.set_text((_("Modify File Labeling for %s. File labels will be created when update is applied.")) % self.application)
            self.files_popup_window.set_title((_("Add File Labeling for %s")) % self.application)
            self.delete_old_item = None
            self.init_files_dialog(args)
            self.modify = True
            operation = "Modify"
            mls = 1
            ipage = self.inner_notebook_files.get_current_page()

            if ipage == EXE_PAGE:
                iter = self.executable_files_filter.convert_iter_to_child_iter(iter)
                self.delete_old_item = iter
                path = self.executable_files_liststore.get_value(iter, 0)
                self.files_path_entry.set_text(path)
                ftype = self.executable_files_liststore.get_value(iter, 1)
                if type != None:
                    self.combo_set_active_text(self.files_type_combobox, ftype)
                tclass = self.executable_files_liststore.get_value(iter, 2)
                if tclass != None:
                    self.combo_set_active_text(self.files_class_combobox, tclass)

            if ipage == WRITABLE_PAGE:
                iter = self.writable_files_filter.convert_iter_to_child_iter(iter)
                self.delete_old_item = iter
                path = self.writable_files_liststore.get_value(iter, 0)
                self.files_path_entry.set_text(path)
                type = self.writable_files_liststore.get_value(iter, 1)
                if type != None:
                    self.combo_set_active_text(self.files_type_combobox, type)
                tclass = self.writable_files_liststore.get_value(iter, 2)
                if tclass != None:
                    self.combo_set_active_text(self.files_class_combobox, tclass)

            if ipage == APP_PAGE:
                iter = self.application_files_filter.convert_iter_to_child_iter(iter)
                self.delete_old_item = iter
                path = self.application_files_liststore.get_value(iter, 0)
                self.files_path_entry.set_text(path)
                try:
                    get_type = self.application_files_liststore.get_value(iter, 1)
                    get_type = get_type.split("<b>")[1].split("</b>")
                except AttributeError:
                    pass
                type = self.application_files_liststore.get_value(iter, 2)
                if type != None:
                    self.combo_set_active_text(self.files_type_combobox, type)
                tclass = get_type[0]
                if tclass != None:
                    self.combo_set_active_text(self.files_class_combobox, tclass)

        if self.opage == USER_PAGE:
            self.user_init_dialog(args)
            self.user_name_entry.set_text(self.user_liststore.get_value(iter, 0))
            self.user_mls_level_entry.set_text(self.user_liststore.get_value(iter, 2))
            self.user_mls_entry.set_text(self.user_liststore.get_value(iter, 3))
            self.combo_set_active_text(self.user_roles_combobox, self.user_liststore.get_value(iter, 1))
            self.user_label.set_text((_("Modify SELinux User Role. SELinux user roles will be modified when update is applied.")))
            self.user_popup_window.set_title(_("Modify SELinux Users"))
            self.show_popup(self.user_popup_window)

        if self.opage == LOGIN_PAGE:
            self.login_init_dialog(args)
            self.login_name_entry.set_text(self.login_liststore.get_value(iter, 0))
            self.login_mls_entry.set_text(self.login_liststore.get_value(iter, 2))
            self.combo_set_active_text(self.login_seuser_combobox, self.login_liststore.get_value(iter, 1))
            self.login_label.set_text((_("Modify Login Mapping. Login Mapping will be modified when Update is applied.")))
            self.login_popup_window.set_title(_("Modify Login Mapping"))
            self.show_popup(self.login_popup_window)

        if self.opage == FILE_EQUIV_PAGE:
            self.file_equiv_source_entry.set_text(self.unmarkup(self.file_equiv_liststore.get_value(iter, 0)))
            self.file_equiv_dest_entry.set_text(self.unmarkup(self.file_equiv_liststore.get_value(iter, 1)))
            self.file_equiv_label.set_text((_("Modify File Equivalency Mapping. Mapping will be created when update is applied.")))
            self.file_equiv_popup_window.set_title(_("Modify SELinux File Equivalency"))
            self.clear_entry = True
            self.show_popup(self.file_equiv_popup_window)

    def populate_type_combo(self, tree, loc, *args):
        iter = self.more_types_files_liststore.get_iter(loc)
        ftype = self.more_types_files_liststore.get_value(iter, 0)
        self.combo_set_active_text(self.files_type_combobox, ftype)
        self.show_popup(self.files_popup_window)
        self.moreTypes_window_files.hide()

    def strip_domain(self, domain):
        if domain == None:
            return
        if domain.endswith("_script_t"):
            split_char = "_script_t"
        else:
            split_char = "_t"
        return domain.split(split_char)[0]

    def exclude_type(self, type, exclude_list):
        for e in exclude_list:
            if type.startswith(e):
                return True
        return False

    def init_files_dialog(self, *args):
        exclude_list = []
        self.files_class_combobox.set_sensitive(True)
        self.show_popup(self.files_popup_window)
        ipage = self.inner_notebook_files.get_current_page()
        self.files_type_combolist.clear()
        self.files_class_combolist.clear()
        compare = self.strip_domain(self.application)
        for d in self.application_liststore:
            if d[0].startswith(compare) and d[0] != self.application and not d[0].startswith("httpd_sys"):
                exclude_list.append(self.strip_domain(d[0]))

        self.more_types_files_liststore.clear()
        try:
            for files in sepolicy.file_type_str:
                iter = self.files_class_combolist.append()
                self.files_class_combolist.set_value(iter, 0, sepolicy.file_type_str[files])

            if ipage == EXE_PAGE and self.entrypoints != None:
                for exe in self.entrypoints.keys():
                    if exe.startswith(compare):
                        iter = self.files_type_combolist.append()
                        self.files_type_combolist.set_value(iter, 0, exe)
                    iter = self.more_types_files_liststore.append()
                    self.more_types_files_liststore.set_value(iter, 0, exe)
                self.files_class_combobox.set_active(4)
                self.files_class_combobox.set_sensitive(False)

            elif ipage == WRITABLE_PAGE and self.writable_files != None:
                for write in self.writable_files.keys():
                    if write.startswith(compare) and not self.exclude_type(write, exclude_list) and write in self.file_types:
                        iter = self.files_type_combolist.append()
                        self.files_type_combolist.set_value(iter, 0, write)
                    iter = self.more_types_files_liststore.append()
                    self.more_types_files_liststore.set_value(iter, 0, write)
                self.files_class_combobox.set_active(0)
            elif ipage == APP_PAGE and self.file_types != None:
                for app in sepolicy.get_all_file_types():
                    if app.startswith(compare):
                        if app.startswith(compare) and not self.exclude_type(app, exclude_list):
                            iter = self.files_type_combolist.append()
                            self.files_type_combolist.set_value(iter, 0, app)
                        iter = self.more_types_files_liststore.append()
                        self.more_types_files_liststore.set_value(iter, 0, app)
                self.files_class_combobox.set_active(0)
        except AttributeError:
            print("error")
            pass
        self.files_type_combobox.set_active(0)
        self.files_mls_entry.set_text("s0")
        iter = self.files_type_combolist.append()
        self.files_type_combolist.set_value(iter, 0, _('More...'))

    def modify_button_network_clicked(self, *args):
        iter = self.get_selected_iter()
        if not iter:
            self.modify_button.set_sensitive(False)
            return

        self.popup_network_label.set_text((_("Modify Network Port for %s.  Ports will be created when update is applied.")) % self.application)
        self.network_popup_window.set_title((_("Modify Network Port for %s")) % self.application)
        self.delete_old_item = None
        self.init_network_dialog(args)
        operation = "Modify"
        mls = 1
        self.modify = True
        iter = self.get_selected_iter()
        port = self.liststore.get_value(iter, 0)
        self.network_ports_entry.set_text(port)
        protocol = self.liststore.get_value(iter, 1)
        if protocol == "tcp":
            self.network_tcp_button.set_active(True)
        elif protocol == "udp":
            self.network_udp_button.set_active(True)
        type = self.liststore.get_value(iter, 2)
        if type != None:
            self.combo_set_active_text(self.network_port_type_combobox, type)
        self.delete_old_item = iter

    def init_network_dialog(self, *args):
        self.show_popup(self.network_popup_window)
        ipage = self.inner_notebook_network.get_current_page()
        self.network_port_type_combolist.clear()
        self.network_ports_entry.set_text("")

        try:
            if ipage == OUTBOUND_PAGE:
                netd = sepolicy.network.get_network_connect(self.application, "tcp", "name_connect", check_bools=True)
            elif ipage == INBOUND_PAGE:
                netd = sepolicy.network.get_network_connect(self.application, "tcp", "name_bind", check_bools=True)
                netd += sepolicy.network.get_network_connect(self.application, "udp", "name_bind", check_bools=True)

            port_types = []
            for k in netd.keys():
                for t, ports in netd[k]:
                    if t not in port_types + ["port_t", "unreserved_port_t"]:
                        if t.endswith("_type"):
                            continue

                        port_types.append(t)

            port_types.sort()
            short_domain = self.strip_domain(self.application)
            if short_domain[-1] == "d":
                short_domain = short_domain[:-1]
            short_domain = short_domain + "_"
            ctr = 0
            found = 0
            for t in port_types:
                if t.startswith(short_domain):
                    found = ctr
                iter = self.network_port_type_combolist.append()
                self.network_port_type_combolist.set_value(iter, 0, t)
                ctr += 1
            self.network_port_type_combobox.set_active(found)

        except AttributeError:
            pass

        self.network_tcp_button.set_active(True)
        self.network_mls_entry.set_text("s0")

    def login_seuser_combobox_change(self, combo, *args):
        seuser = self.combo_get_active_text(combo)
        if self.login_mls_entry.get_text() == "":
            for u in sepolicy.get_selinux_users():
                if seuser == u['name']:
                    self.login_mls_entry.set_text(u.get('range', ''))

    def user_roles_combobox_change(self, combo, *args):
        serole = self.combo_get_active_text(combo)
        if self.user_mls_entry.get_text() == "":
            for u in sepolicy.get_all_roles():
                if serole == u['name']:
                    self.user_mls_entry.set_text(u.get('range', ''))

    def get_selected_iter(self):
        iter = None
        if not self.treeview:
            return None
        row = self.treeview.get_selection()
        if not row:
            return None
        treesort, iter = row.get_selected()
        if iter:
            iter = treesort.convert_iter_to_child_iter(iter)
            if iter:
                iter = self.treefilter.convert_iter_to_child_iter(iter)
        return iter

    def cursor_changed(self, *args):
        self.modify_button.set_sensitive(False)
        iter = self.get_selected_iter()
        if iter == None:
            self.modify_button.set_sensitive(False)
            return
        if not self.liststore[iter] or not self.liststore[iter][-1]:
            return
        self.modify_button.set_sensitive(self.liststore[iter][-1])

    def login_init_dialog(self, *args):
        self.show_popup(self.login_popup_window)
        self.login_seuser_combolist.clear()
        users = sepolicy.get_all_users()
        users.sort()
        for u in users:
            iter = self.login_seuser_combolist.append()
            self.login_seuser_combolist.set_value(iter, 0, str(u))
        self.login_name_entry.set_text("")
        self.login_mls_entry.set_text("")

    def user_init_dialog(self, *args):
        self.show_popup(self.user_popup_window)
        self.user_roles_combolist.clear()
        roles = sepolicy.get_all_roles()
        roles.sort()
        for r in roles:
            iter = self.user_roles_combolist.append()
            self.user_roles_combolist.set_value(iter, 0, str(r))
        self.user_name_entry.set_text("")
        self.user_mls_entry.set_text("")

    def on_disable_ptrace(self, checkbutton):
        if self.finish_init:
            update_buffer = "boolean -m -%d deny_ptrace" % checkbutton.get_active()
            self.wait_mouse()
            try:
                self.dbus.semanage(update_buffer)
            except dbus.exceptions.DBusException as e:
                self.error(e)
            self.ready_mouse()

    def on_show_modified_only(self, checkbutton):
        length = self.liststore.get_n_columns()

        def dup_row(row):
            l = []
            for i in range(0, length):
                l.append(row[i])
            return l

        append_list = []
        if self.opage == BOOLEANS_PAGE:
            if not checkbutton.get_active():
                return self.boolean_initialize(self.application)

            for row in self.liststore:
                if row[2] in self.cust_dict["boolean"]:
                    append_list.append(dup_row(row))

        if self.opage == FILES_PAGE:
            ipage = self.inner_notebook_files.get_current_page()
            if not checkbutton.get_active():
                if ipage == EXE_PAGE:
                    return self.executable_files_initialize(self.application)
                if ipage == WRITABLE_PAGE:
                    return self.writable_files_initialize(self.application)
                if ipage == APP_PAGE:
                    return self.application_files_initialize(self.application)
            for row in self.liststore:
                if (row[0], row[2]) in self.cust_dict["fcontext"]:
                    append_list.append(row)

        if self.opage == NETWORK_PAGE:
            if not checkbutton.get_active():
                return self.network_initialize(self.application)
            for row in self.liststore:
                if (row[0], row[1]) in self.cust_dict["port"]:
                    append_list.append(dup_row(row))

        if self.opage == FILE_EQUIV_PAGE:
            if not checkbutton.get_active() == True:
                return self.file_equiv_initialize()

            for row in self.liststore:
                if row[0] in self.cust_dict["fcontext-equiv"]:
                    append_list.append(dup_row(row))

        if self.opage == USER_PAGE:
            if not checkbutton.get_active():
                return self.user_initialize()

            for row in self.liststore:
                if row[0] in self.cust_dict["user"]:
                    append_list.append(dup_row(row))

        if self.opage == LOGIN_PAGE:
            if not checkbutton.get_active() == True:
                return self.login_initialize()

            for row in self.liststore:
                if row[0] in self.cust_dict["login"]:
                    append_list.append(dup_row(row))

        self.liststore.clear()
        for row in append_list:
            iter = self.liststore.append()
            for i in range(0, length):
                self.liststore.set_value(iter, i, row[i])

    def init_modified_files_liststore(self, tree, app, ipage, operation, path, fclass, ftype):
        iter = tree.append(None)
        tree.set_value(iter, 0, path)
        tree.set_value(iter, 1, ftype)
        tree.set_value(iter, 2, fclass)

    def restore_to_default(self, *args):
        print("restore to defualt clicked...")

    def invalid_entry_retry(self, *args):
        self.closewindow(self.error_check_window)
        self.files_popup_window.set_sensitive(True)
        self.network_popup_window.set_sensitive(True)

    def error_check_files(self, insert_txt):
        if len(insert_txt) == 0 or insert_txt[0] != '/':
            self.error_check_window.show()
            self.files_popup_window.set_sensitive(False)
            self.network_popup_window.set_sensitive(False)
            self.error_check_label.set_text((_("The entry '%s' is not a valid path.  Paths must begin with a '/'.")) % insert_txt)
            return True
        return False

    def error_check_network(self, port):
        try:
            pnum = int(port)
            if pnum < 1 or pnum > 65536:
                raise ValueError
        except ValueError:
            self.error_check_window.show()
            self.files_popup_window.set_sensitive(False)
            self.network_popup_window.set_sensitive(False)
            self.error_check_label.set_text((_("Port number must be between 1 and 65536")))
            return True
        return False

    def show_more_types(self, *args):
        if self.finish_init:
            if self.combo_get_active_text(self.files_type_combobox) == _('More...'):
                self.files_popup_window.hide()
                self.moreTypes_window_files.show()

    def update_to_login(self, *args):
        self.close_popup()
        seuser = self.combo_get_active_text(self.login_seuser_combobox)
        mls_range = self.login_mls_entry.get_text()
        name = self.login_name_entry.get_text()
        if self.modify:
            iter = self.get_selected_iter()
            oldname = self.login_liststore.get_value(iter, 0)
            oldseuser = self.login_liststore.get_value(iter, 1)
            oldrange = self.login_liststore.get_value(iter, 2)
            self.liststore.set_value(iter, 0, oldname)
            self.liststore.set_value(iter, 1, oldseuser)
            self.liststore.set_value(iter, 2, oldrange)
            self.cur_dict["login"][name] = {"action": "-m", "range": mls_range, "seuser": seuser, "oldrange": oldrange, "oldseuser": oldseuser, "oldname": oldname}
        else:
            iter = self.liststore.append(None)
            self.cur_dict["login"][name] = {"action": "-a", "range": mls_range, "seuser": seuser}

        self.liststore.set_value(iter, 0, name)
        self.liststore.set_value(iter, 1, seuser)
        self.liststore.set_value(iter, 2, mls_range)

        self.new_updates()

    def update_to_user(self, *args):
        self.close_popup()
        roles = self.combo_get_active_text(self.user_roles_combobox)
        level = self.user_mls_level_entry.get_text()
        mls_range = self.user_mls_entry.get_text()
        name = self.user_name_entry.get_text()
        if self.modify:
            iter = self.get_selected_iter()
            oldname = self.user_liststore.get_value(iter, 0)
            oldroles = self.user_liststore.get_value(iter, 1)
            oldlevel = self.user_liststore.get_value(iter, 1)
            oldrange = self.user_liststore.get_value(iter, 3)
            self.liststore.set_value(iter, 0, oldname)
            self.liststore.set_value(iter, 1, oldroles)
            self.liststore.set_value(iter, 2, oldlevel)
            self.liststore.set_value(iter, 3, oldrange)
            self.cur_dict["user"][name] = {"action": "-m", "range": mls_range, "level": level, "role": roles, "oldrange": oldrange, "oldlevel": oldlevel, "oldroles": oldroles, "oldname": oldname}
        else:
            iter = self.liststore.append(None)
            if mls_range or level:
                self.cur_dict["user"][name] = {"action": "-a", "range": mls_range, "level": level, "role": roles}
            else:
                self.cur_dict["user"][name] = {"action": "-a", "role": roles}

        self.liststore.set_value(iter, 0, name)
        self.liststore.set_value(iter, 1, roles)
        self.liststore.set_value(iter, 2, level)
        self.liststore.set_value(iter, 3, mls_range)

        self.new_updates()

    def update_to_file_equiv(self, *args):
        self.close_popup()
        dest = self.file_equiv_dest_entry.get_text()
        src = self.file_equiv_source_entry.get_text()
        if self.modify:
            iter = self.get_selected_iter()
            olddest = self.unmarkup(self.liststore.set_value(iter, 0))
            oldsrc = self.unmarkup(self.liststore.set_value(iter, 1))
            self.cur_dict["fcontext-equiv"][dest] = {"action": "-m", "src": src, "oldsrc": oldsrc, "olddest": olddest}
        else:
            iter = self.liststore.append(None)
            self.cur_dict["fcontext-equiv"][dest] = {"action": "-a", "src": src}
        self.liststore.set_value(iter, 0, self.markup(dest))
        self.liststore.set_value(iter, 1, self.markup(src))

    def update_to_files(self, *args):
        self.close_popup()
        self.files_add = True
        # Insert Function will be used in the future
        path = self.files_path_entry.get_text()
        if self.error_check_files(path):
            return

        setype = self.combo_get_active_text(self.files_type_combobox)
        mls = self.files_mls_entry.get_text()
        tclass = self.combo_get_active_text(self.files_class_combobox)

        if self.modify:
            iter = self.get_selected_iter()
            oldpath = self.unmark(self.liststore.get_value(iter, 0))
            setype = self.unmark(self.liststore.set_value(iter, 1))
            oldtclass = self.liststore.get_value(iter, 2)
            self.cur_dict["fcontext"][(path, tclass)] = {"action": "-m", "type": setype, "oldtype": oldsetype, "oldmls": oldmls, "oldclass": oldclass}
        else:
            iter = self.liststore.append(None)
            self.cur_dict["fcontext"][(path, tclass)] = {"action": "-a", "type": setype}
        self.liststore.set_value(iter, 0, self.markup(path))
        self.liststore.set_value(iter, 1, self.markup(setype))
        self.liststore.set_value(iter, 2, self.markup(tclass))

        self.files_add = False
        self.recursive_path_toggle.set_active(False)
        self.new_updates()

    def update_to_network(self, *args):
        self.network_add = True
        ports = self.network_ports_entry.get_text()
        if self.error_check_network(ports):
            return
        if self.network_tcp_button.get_active():
            protocol = "tcp"
        else:
            protocol = "udp"

        setype = self.combo_get_active_text(self.network_port_type_combobox)
        mls = self.network_mls_entry.get_text()

        if self.modify:
            iter = self.get_selected_iter()
            oldports = self.unmark(self.liststore.get_value(iter, 0))
            oldprotocol = self.unmark(self.liststore.get_value(iter, 1))
            oldsetype = self.unmark(self.liststore.set_value(iter, 2))
            self.cur_dict["port"][(ports, protocol)] = {"action": "-m", "type": setype, "mls": mls, "oldtype": oldsetype, "oldmls": oldmls, "oldprotocol": oldprotocol, "oldports": oldports}
        else:
            iter = self.liststore.append(None)
            self.cur_dict["port"][(ports, protocol)] = {"action": "-a", "type": setype, "mls": mls}
        self.liststore.set_value(iter, 0, ports)
        self.liststore.set_value(iter, 1, protocol)
        self.liststore.set_value(iter, 2, setype)

        self.network_add = False
        self.network_popup_window.hide()
        self.window.set_sensitive(True)
        self.new_updates()

    def delete_button_clicked(self, *args):
        operation = "Add"
        self.window.set_sensitive(False)
        if self.opage == NETWORK_PAGE:
            self.network_delete_liststore.clear()
            port_dict = self.cust_dict["port"]
            for ports, protocol in port_dict:
                setype = port_dict[(ports, protocol)]["type"]
                iter = self.network_delete_liststore.append()
                self.network_delete_liststore.set_value(iter, 1, ports)
                self.network_delete_liststore.set_value(iter, 2, protocol)
                self.network_delete_liststore.set_value(iter, 3, setype)
            self.show_popup(self.network_delete_window)
            return

        if self.opage == FILES_PAGE:
            self.files_delete_liststore.clear()
            fcontext_dict = self.cust_dict["fcontext"]
            for path, tclass in fcontext_dict:
                setype = fcontext_dict[(path, tclass)]["type"]
                iter = self.files_delete_liststore.append()
                self.files_delete_liststore.set_value(iter, 1, path)
                self.files_delete_liststore.set_value(iter, 2, setype)
                self.files_delete_liststore.set_value(iter, 3, sepolicy.file_type_str[tclass])
            self.show_popup(self.files_delete_window)
            return

        if self.opage == USER_PAGE:
            self.user_delete_liststore.clear()
            user_dict = self.cust_dict["user"]
            for user in user_dict:
                roles = user_dict[user]["role"]
                mls = user_dict[user].get("range", "")
                level = user_dict[user].get("level", "")
                iter = self.user_delete_liststore.append()
                self.user_delete_liststore.set_value(iter, 1, user)
                self.user_delete_liststore.set_value(iter, 2, roles)
                self.user_delete_liststore.set_value(iter, 3, level)
                self.user_delete_liststore.set_value(iter, 4, mls)
            self.show_popup(self.user_delete_window)
            return

        if self.opage == LOGIN_PAGE:
            self.login_delete_liststore.clear()
            login_dict = self.cust_dict["login"]
            for login in login_dict:
                seuser = login_dict[login]["seuser"]
                mls = login_dict[login].get("range", "")
                iter = self.login_delete_liststore.append()
                self.login_delete_liststore.set_value(iter, 1, seuser)
                self.login_delete_liststore.set_value(iter, 2, login)
                self.login_delete_liststore.set_value(iter, 3, mls)
            self.show_popup(self.login_delete_window)
            return

        if self.opage == FILE_EQUIV_PAGE:
            self.file_equiv_delete_liststore.clear()
            for items in self.file_equiv_liststore:
                if items[2]:
                    iter = self.file_equiv_delete_liststore.append()
                    self.file_equiv_delete_liststore.set_value(iter, 1, self.unmarkup(items[0]))
                    self.file_equiv_delete_liststore.set_value(iter, 2, self.unmarkup(items[1]))
            self.show_popup(self.file_equiv_delete_window)
            return

    def on_save_delete_clicked(self, *args):
        self.close_popup()
        if self.opage == NETWORK_PAGE:
            for delete in self.network_delete_liststore:
                if delete[0]:
                    self.cur_dict["port"][(delete[1], delete[2])] = {"action": "-d", "type": delete[3]}
        if self.opage == FILES_PAGE:
            for delete in self.files_delete_liststore:
                if delete[0]:
                    self.cur_dict["fcontext"][(delete[1], reverse_file_type_str[delete[3]])] = {"action": "-d", "type": delete[2]}
        if self.opage == USER_PAGE:
            for delete in self.user_delete_liststore:
                if delete[0]:
                    self.cur_dict["user"][delete[1]] = {"action": "-d", "role": delete[2], "range": delete[4]}
        if self.opage == LOGIN_PAGE:
            for delete in self.login_delete_liststore:
                if delete[0]:
                    self.cur_dict["login"][delete[2]] = {"action": "-d", "login": delete[2], "seuser": delete[1], "range": delete[3]}
        if self.opage == FILE_EQUIV_PAGE:
            for delete in self.file_equiv_delete_liststore:
                if delete[0]:
                    self.cur_dict["fcontext-equiv"][delete[1]] = {"action": "-d", "src": delete[2]}
        self.new_updates()

    def on_save_delete_file_equiv_clicked(self, *args):
        for delete in self.files_delete_liststore:
            print(delete[0], delete[1], delete[2],)

    def on_toggle_update(self, cell, path, model):
        model[path][0] = not model[path][0]

    def ipage_delete(self, liststore, key):
        ctr = 0
        for items in liststore:
            if items[0] == key[0] and items[2] == key[1]:
                iter = liststore.get_iter(ctr)
                liststore.remove(iter)
                return
            ctr += 1

    def on_toggle(self, cell, path, model):
        if not path:
            return
        iter = self.boolean_filter.get_iter(path)
        iter = self.boolean_filter.convert_iter_to_child_iter(iter)
        name = model.get_value(iter, 2)
        model.set_value(iter, 0, not model.get_value(iter, 0))
        active = model.get_value(iter, 0)
        if name in self.cur_dict["boolean"]:
            del(self.cur_dict["boolean"][name])
        else:
            self.cur_dict["boolean"][name] = {"active": active}
        self.new_updates()

    def get_advanced_filter_data(self, entry, *args):
        self.filter_txt = entry.get_text()
        self.advanced_search_filter.refilter()

    def get_filter_data(self, windows, *args):
        #search for desired item
        # The txt that the use rinputs into the filter is stored in filter_txt
        self.filter_txt = windows.get_text()
        self.treefilter.refilter()

    def update_gui(self, *args):
        self.update = True
        self.update_treestore.clear()
        for bools in self.cur_dict["boolean"]:
            operation = self.cur_dict["boolean"][bools]["action"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 1, sepolicy.boolean_desc(bools))
            self.update_treestore.set_value(iter, 2, action[self.cur_dict["boolean"][bools]['active']])
            self.update_treestore.set_value(iter, 3, True)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 1, (_("SELinux name: %s")) % bools)
            self.update_treestore.set_value(niter, 3, False)

        for path, tclass in self.cur_dict["fcontext"]:
            operation = self.cur_dict["fcontext"][(path, tclass)]["action"]
            setype = self.cur_dict["fcontext"][(path, tclass)]["type"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 2, operation)
            self.update_treestore.set_value(iter, 0, True)
            if operation == "-a":
                self.update_treestore.set_value(iter, 1, (_("Add file labeling for %s")) % self.application)
            if operation == "-d":
                self.update_treestore.set_value(iter, 1, (_("Delete file labeling for %s")) % self.application)
            if operation == "-m":
                self.update_treestore.set_value(iter, 1, (_("Modify file labeling for %s")) % self.application)

            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("File path: %s")) % path)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("File class: %s")) % sepolicy.file_type_str[tclass])
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("SELinux file type: %s")) % setype)

        for port, protocol in self.cur_dict["port"]:
            operation = self.cur_dict["port"][(port, protocol)]["action"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 2, operation)
            self.update_treestore.set_value(iter, 3, True)
            if operation == "-a":
                self.update_treestore.set_value(iter, 1, (_("Add ports for %s")) % self.application)
            if operation == "-d":
                self.update_treestore.set_value(iter, 1, (_("Delete ports for %s")) % self.application)
            if operation == "-m":
                self.update_treestore.set_value(iter, 1, (_("Modify ports for %s")) % self.application)

            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 1, (_("Network ports: %s")) % port)
            self.update_treestore.set_value(niter, 3, False)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 1, (_("Network protocol: %s")) % protocol)
            self.update_treestore.set_value(niter, 3, False)
            setype = self.cur_dict["port"][(port, protocol)]["type"]
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("SELinux file type: %s")) % setype)

        for user in self.cur_dict["user"]:
            operation = self.cur_dict["user"][user]["action"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 2, operation)
            self.update_treestore.set_value(iter, 0, True)
            if operation == "-a":
                self.update_treestore.set_value(iter, 1, _("Add user"))
            if operation == "-d":
                self.update_treestore.set_value(iter, 1, _("Delete user"))
            if operation == "-m":
                self.update_treestore.set_value(iter, 1, _("Modify user"))

            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 1, (_("SELinux User : %s")) % user)
            self.update_treestore.set_value(niter, 3, False)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            roles = self.cur_dict["user"][user]["role"]
            self.update_treestore.set_value(niter, 1, (_("Roles: %s")) % roles)
            mls = self.cur_dict["user"][user].get("range", "")
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, _("MLS/MCS Range: %s") % mls)

        for login in self.cur_dict["login"]:
            operation = self.cur_dict["login"][login]["action"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 2, operation)
            self.update_treestore.set_value(iter, 0, True)
            if operation == "-a":
                self.update_treestore.set_value(iter, 1, _("Add login mapping"))
            if operation == "-d":
                self.update_treestore.set_value(iter, 1, _("Delete login mapping"))
            if operation == "-m":
                self.update_treestore.set_value(iter, 1, _("Modify login mapping"))

            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("Login Name : %s")) % login)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            seuser = self.cur_dict["login"][login]["seuser"]
            self.update_treestore.set_value(niter, 1, (_("SELinux User: %s")) % seuser)
            mls = self.cur_dict["login"][login].get("range", "")
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, _("MLS/MCS Range: %s") % mls)

        for path in self.cur_dict["fcontext-equiv"]:
            operation = self.cur_dict["fcontext-equiv"][path]["action"]
            iter = self.update_treestore.append(None)
            self.update_treestore.set_value(iter, 0, True)
            self.update_treestore.set_value(iter, 2, operation)
            self.update_treestore.set_value(iter, 0, True)
            if operation == "-a":
                self.update_treestore.set_value(iter, 1, (_("Add file equiv labeling.")))
            if operation == "-d":
                self.update_treestore.set_value(iter, 1, (_("Delete file equiv labeling.")))
            if operation == "-m":
                self.update_treestore.set_value(iter, 1, (_("Modify file equiv labeling.")))

            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            self.update_treestore.set_value(niter, 1, (_("File path : %s")) % path)
            niter = self.update_treestore.append(iter)
            self.update_treestore.set_value(niter, 3, False)
            src = self.cur_dict["fcontext-equiv"][path]["src"]
            self.update_treestore.set_value(niter, 1, (_("Equivalence: %s")) % src)

        self.show_popup(self.update_window)

    def set_active_application_button(self):
        if self.boolean_radio_button.get_active():
            self.active_button = self.boolean_radio_button
        if self.files_radio_button.get_active():
            self.active_button = self.files_radio_button
        if self.transitions_radio_button.get_active():
            self.active_button = self.transitions_radio_button
        if self.network_radio_button.get_active():
            self.active_button = self.network_radio_button

    def clearbuttons(self, clear=True):
        self.main_selection_window.hide()
        self.boolean_radio_button.set_visible(False)
        self.files_radio_button.set_visible(False)
        self.network_radio_button.set_visible(False)
        self.transitions_radio_button.set_visible(False)
        self.system_radio_button.set_visible(False)
        self.lockdown_radio_button.set_visible(False)
        self.user_radio_button.set_visible(False)
        self.login_radio_button.set_visible(False)
        if clear:
            self.completion_entry.set_text("")

    def show_system_page(self):
        self.clearbuttons()
        self.system_radio_button.set_visible(True)
        self.lockdown_radio_button.set_visible(True)
        self.applications_selection_button.set_label(_("System"))
        self.system_radio_button.set_active(True)
        self.tab_change()
        self.idle_func()

    def show_file_equiv_page(self, *args):
        self.clearbuttons()
        self.file_equiv_initialize()
        self.file_equiv_radio_button.set_active(True)
        self.applications_selection_button.set_label(_("File Equivalence"))
        self.tab_change()
        self.idle_func()
        self.add_button.set_sensitive(True)
        self.delete_button.set_sensitive(True)

    def show_users_page(self):
        self.clearbuttons()
        self.login_radio_button.set_visible(True)
        self.user_radio_button.set_visible(True)
        self.applications_selection_button.set_label(_("Users"))
        self.login_radio_button.set_active(True)
        self.tab_change()
        self.user_initialize()
        self.login_initialize()
        self.idle_func()
        self.add_button.set_sensitive(True)
        self.delete_button.set_sensitive(True)

    def show_applications_page(self):
        self.clearbuttons(False)
        self.boolean_radio_button.set_visible(True)
        self.files_radio_button.set_visible(True)
        self.network_radio_button.set_visible(True)
        self.transitions_radio_button.set_visible(True)
        self.boolean_radio_button.set_active(True)
        self.tab_change()
        self.idle_func()

    def system_interface(self, *args):
        self.show_system_page()

    def users_interface(self, *args):
        self.show_users_page()

    def show_mislabeled_files(self, checkbutton, *args):
        iterlist = []
        ctr = 0
        ipage = self.inner_notebook_files.get_current_page()
        if checkbutton.get_active() == True:
            for items in self.liststore:
                iter = self.treesort.get_iter(ctr)
                iter = self.treesort.convert_iter_to_child_iter(iter)
                iter = self.treefilter.convert_iter_to_child_iter(iter)
                if iter != None:
                    if self.liststore.get_value(iter, 4) == False:
                        iterlist.append(iter)
                    ctr += 1
            for iters in iterlist:
                self.liststore.remove(iters)

        elif self.application != None:
            self.liststore.clear()
            if ipage == EXE_PAGE:
                self.executable_files_initialize(self.application)
            elif ipage == WRITABLE_PAGE:
                self.writable_files_initialize(self.application)
            elif ipage == APP_PAGE:
                self.application_files_initialize(self.application)

    def fix_mislabeled(self, path):
        cur = selinux.getfilecon(path)[1].split(":")[2]
        con = selinux.matchpathcon(path, 0)[1].split(":")[2]
        if self.verify(_("Run restorecon on %(PATH)s to change its type from %(CUR_CONTEXT)s to the default %(DEF_CONTEXT)s?") % {"PATH": path, "CUR_CONTEXT": cur, "DEF_CONTEXT": con}, title="restorecon dialog") == Gtk.ResponseType.YES:
            self.dbus.restorecon(path)
            self.application_selected()

    def new_updates(self, *args):
        self.update_button.set_sensitive(self.modified())
        self.revert_button.set_sensitive(self.modified())

    def update_or_revert_changes(self, button, *args):
        self.update_gui()
        self.update = (button.get_label() == _("Update"))
        if self.update:
            self.update_window.set_title(_("Update Changes"))
        else:
            self.update_window.set_title(_("Revert Changes"))

    def apply_changes_button_press(self, *args):
        self.close_popup()
        if self.update:
            self.update_the_system()
        else:
            self.revert_data()
        self.finish_init = False
        self.previously_modified_initialize(self.dbus.customized())
        self.finish_init = True
        self.clear_filters()
        self.application_selected()
        self.new_updates()
        self.update_treestore.clear()

    def update_the_system(self, *args):
        self.close_popup()
        update_buffer = self.format_update()
        self.wait_mouse()
        try:
            self.dbus.semanage(update_buffer)
        except dbus.exceptions.DBusException as e:
            print(e)
        self.ready_mouse()
        self.init_cur()

    def ipage_value_lookup(self, lookup):
        ipage_values = {"Executable Files": 0, "Writable Files": 1, "Application File Type": 2, "Inbound": 1, "Outbound": 0}
        for value in ipage_values:
            if value == lookup:
                return ipage_values[value]
        return "Booleans"

    def get_attributes_update(self, attribute):
        attribute = attribute.split(": ")[1]
        bool_id = attribute.split(": ")[0]
        if bool_id == "SELinux name":
            self.bool_revert = attribute
        else:
            return attribute

    def format_update(self):
        self.revert_data()
        update_buffer = ""
        for k in self.cur_dict:
            if k in "boolean":
                for b in self.cur_dict[k]:
                    update_buffer += "boolean -m -%d %s\n" % (self.cur_dict[k][b]["active"], b)
            if k in "login":
                for l in self.cur_dict[k]:
                    if self.cur_dict[k][l]["action"] == "-d":
                        update_buffer += "login -d %s\n" % l
                    elif "range" in self.cur_dict[k][l]:
                        update_buffer += "login %s -s %s -r %s %s\n" % (self.cur_dict[k][l]["action"], self.cur_dict[k][l]["seuser"], self.cur_dict[k][l]["range"], l)
                    else:
                        update_buffer += "login %s -s %s %s\n" % (self.cur_dict[k][l]["action"], self.cur_dict[k][l]["seuser"], l)
            if k in "user":
                for u in self.cur_dict[k]:
                    if self.cur_dict[k][u]["action"] == "-d":
                        update_buffer += "user -d %s\n" % u
                    elif "level" in self.cur_dict[k][u] and "range" in self.cur_dict[k][u]:
                        update_buffer += "user %s -L %s -r %s -R %s %s\n" % (self.cur_dict[k][u]["action"], self.cur_dict[k][u]["level"], self.cur_dict[k][u]["range"], self.cur_dict[k][u]["role"], u)
                    else:
                        update_buffer += "user %s -R %s %s\n" % (self.cur_dict[k][u]["action"], self.cur_dict[k][u]["role"], u)

            if k in "fcontext-equiv":
                for f in self.cur_dict[k]:
                    if self.cur_dict[k][f]["action"] == "-d":
                        update_buffer += "fcontext -d %s\n" % f
                    else:
                        update_buffer += "fcontext %s -e %s %s\n" % (self.cur_dict[k][f]["action"], self.cur_dict[k][f]["src"], f)

            if k in "fcontext":
                for f in self.cur_dict[k]:
                    if self.cur_dict[k][f]["action"] == "-d":
                        update_buffer += "fcontext -d %s\n" % f
                    else:
                        update_buffer += "fcontext %s -t %s -f %s %s\n" % (self.cur_dict[k][f]["action"], self.cur_dict[k][f]["type"], self.cur_dict[k][f]["class"], f)

            if k in "port":
                for port, protocol in self.cur_dict[k]:
                    if self.cur_dict[k][(port, protocol)]["action"] == "-d":
                        update_buffer += "port -d -p %s %s\n" % (protocol, port)
                    else:
                        update_buffer += "port %s -t %s -p %s %s\n" % (self.cur_dict[k][f]["action"], self.cur_dict[k][f]["type"], procotol, port)

        return update_buffer

    def revert_data(self):
        ctr = 0
        remove_list = []
        update_buffer = ""
        for items in self.update_treestore:
            if not self.update_treestore[ctr][0]:
                remove_list.append(ctr)
            ctr += 1
        remove_list.reverse()
        for ctr in remove_list:
            self.remove_cur(ctr)

    def reveal_advanced_system(self, label, *args):
        advanced = label.get_text() == ADVANCED_LABEL[0]
        if advanced:
            label.set_text(ADVANCED_LABEL[1])
        else:
            label.set_text(ADVANCED_LABEL[0])
        self.system_policy_label.set_visible(advanced)
        self.system_policy_type_combobox.set_visible(advanced)

    def reveal_advanced(self, label, *args):
        advanced = label.get_text() == ADVANCED_LABEL[0]
        if advanced:
            label.set_text(ADVANCED_LABEL[1])
        else:
            label.set_text(ADVANCED_LABEL[0])
        self.files_mls_label.set_visible(advanced)
        self.files_mls_entry.set_visible(advanced)
        self.network_mls_label.set_visible(advanced)
        self.network_mls_entry.set_visible(advanced)

    def on_show_advanced_search_window(self, label, *args):
        if label.get_text() == ADVANCED_SEARCH_LABEL[1]:
            label.set_text(ADVANCED_SEARCH_LABEL[0])
            self.close_popup()
        else:
            label.set_text(ADVANCED_SEARCH_LABEL[1])
            self.show_popup(self.advanced_search_window)

    def set_enforce_text(self, value):
        if value:
            self.status_bar.push(self.context_id, _("System Status: Enforcing"))
            self.current_status_enforcing.set_active(True)
        else:
            self.status_bar.push(self.context_id, _("System Status: Permissive"))
            self.current_status_permissive.set_active(True)

    def set_enforce(self, button):
        if not self.finish_init:
            return

        self.dbus.setenforce(button.get_active())
        self.set_enforce_text(button.get_active())

    def on_browse_select(self, *args):
        filename = self.file_dialog.get_filename()
        if filename == None:
            return
        self.clear_entry = False
        self.file_dialog.hide()
        self.files_path_entry.set_text(filename)
        if self.import_export == 'Import':
            self.import_config(filename)
        elif self.import_export == 'Export':
            self.export_config(filename)

    def recursive_path(self, *args):
        path = self.files_path_entry.get_text()
        if self.recursive_path_toggle.get_active():
            if not path.endswith("(/.*)?"):
                self.files_path_entry.set_text(path + "(/.*)?")
        elif path.endswith("(/.*)?"):
            path = path.split("(/.*)?")[0]
            self.files_path_entry.set_text(path)

    def highlight_entry_text(self, entry_obj, *args):
        txt = entry_obj.get_text()
        if self.clear_entry:
            entry_obj.set_text('')
            self.clear_entry = False

    def autofill_add_files_entry(self, entry):
        text = entry.get_text()
        if text == '':
            return
        if text.endswith("(/.*)?"):
            self.recursive_path_toggle.set_active(True)
        for d in sepolicy.DEFAULT_DIRS:
            if text.startswith(d):
                for t in self.files_type_combolist:
                    if t[0].endswith(sepolicy.DEFAULT_DIRS[d]):
                        self.combo_set_active_text(self.files_type_combobox, t[0])

    def resize_columns(self, *args):
        self.boolean_column_1 = self.boolean_treeview.get_col(1)
        width = self.boolean_column_1.get_width()
        renderer = self.boolean_column_1.get_cell_renderers()

    def browse_for_files(self, *args):
        self.file_dialog.show()

    def close_config_window(self, *args):
        self.file_dialog.hide()

    def change_default_policy(self, *args):
        if self.typeHistory == self.system_policy_type_combobox.get_active():
            return

        if self.verify(_("Changing the policy type will cause a relabel of the entire file system on the next boot. Relabeling takes a long time depending on the size of the file system.  Do you wish to continue?")) == Gtk.ResponseType.NO:
            self.system_policy_type_combobox.set_active(self.typeHistory)
            return None

        self.dbus.change_default_policy(self.combo_get_active_text(self.system_policy_type_combobox))
        self.dbus.relabel_on_boot(True)
        self.typeHistory = self.system_policy_type_combobox.get_active()

    def change_default_mode(self, button):
        if not self.finish_init:
            return
        self.enabled_changed(button)
        if button.get_active():
            self.dbus.change_default_mode(button.get_label().lower())

    def import_config_show(self, *args):
        self.file_dialog.set_action(Gtk.FileChooserAction.OPEN)
        self.file_dialog.set_title("Import Configuration")
        self.file_dialog.show()
        #self.file_dialog.set_uri('/tmp')
        self.import_export = 'Import'

    def export_config_show(self, *args):
        self.file_dialog.set_action(Gtk.FileChooserAction.SAVE)
        self.file_dialog.set_title("Export Configuration")
        self.file_dialog.show()
        self.import_export = 'Export'

    def export_config(self, filename):
        self.wait_mouse()
        buf = self.dbus.customized()
        fd = open(filename, 'w')
        fd.write(buf)
        fd.close()
        self.ready_mouse()

    def import_config(self, filename):
        fd = open(filename, "r")
        buf = fd.read()
        fd.close()
        self.wait_mouse()
        try:
            self.dbus.semanage(buf)
        except OSError:
            pass
        self.ready_mouse()

    def init_dictionary(self, dic, app, ipage, operation, p, q, ftype, mls, changed, old):
        if (app, ipage, operation) not in dic:
            dic[app, ipage, operation] = {}
        if (p, q) not in dic[app, ipage, operation]:
            dic[app, ipage, operation][p, q] = {'type': ftype, 'mls': mls, 'changed': changed, 'old': old}

    def translate_bool(self, b):
        b = b.split('-')[1]
        if b == '0':
            return False
        if b == '1':
            return True

    def relabel_on_reboot(self, *args):
        active = self.relabel_button.get_active()
        exists = os.path.exists("/.autorelabel")

        if active and exists:
            return
        if not active and not exists:
            return
        try:
            self.dbus.relabel_on_boot(active)
        except dbus.exceptions.DBusException as e:
            self.error(e)

    def closewindow(self, window, *args):
        window.hide()
        self.recursive_path_toggle.set_active(False)
        self.window.set_sensitive(True)
        if self.moreTypes_window_files == window:
            self.show_popup(self.files_popup_window)
            if self.combo_get_active_text(self.files_type_combobox) == _('More...'):
                self.files_type_combobox.set_active(0)
        if self.error_check_window == window:
            if self.files_add:
                self.show_popup(self.files_popup_window)
            elif self.network_add:
                self.show_popup(self.network_popup_window)
        if self.files_mls_label.get_visible() or self.network_mls_label.get_visible():
            self.advanced_text_files.set_visible(True)
            self.files_mls_label.set_visible(False)
            self.files_mls_entry.set_visible(False)
            self.advanced_text_network.set_visible(True)
            self.network_mls_label.set_visible(False)
            self.network_mls_entry.set_visible(False)
        if self.main_advanced_label.get_text() == ADVANCED_SEARCH_LABEL[1]:
            self.main_advanced_label.set_text(ADVANCED_SEARCH_LABEL[0])
        return True

    def wait_mouse(self):
        self.window.get_window().set_cursor(self.busy_cursor)
        self.idle_func()

    def ready_mouse(self):
        self.window.get_window().set_cursor(self.ready_cursor)
        self.idle_func()

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

    def error(self, message):
        dlg = Gtk.MessageDialog(None, 0, Gtk.MessageType.ERROR,
                                Gtk.ButtonsType.CLOSE,
                                message)
        dlg.set_position(Gtk.WindowPosition.MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def enabled_changed(self, radio):
        if not radio.get_active():
            return
        label = radio.get_label()
        if label == 'Disabled' and self.enforce_mode != DISABLED:
            if self.verify(_("Changing to SELinux disabled requires a reboot.  It is not recommended.  If you later decide to turn SELinux back on, the system will be required to relabel.  If you just want to see if SELinux is causing a problem on your system, you can go to permissive mode which will only log errors and not enforce SELinux policy.  Permissive mode does not require a reboot.  Do you wish to continue?")) == Gtk.ResponseType.NO:
                self.enforce_button.set_active(True)

        if label != 'Disabled' and self.enforce_mode == DISABLED:
            if self.verify(_("Changing to SELinux enabled will cause a relabel of the entire file system on the next boot. Relabeling takes a long time depending on the size of the file system.  Do you wish to continue?")) == Gtk.ResponseType.NO:
                self.enforce_button.set_active(True)
        self.enforce_button = radio

    def clear_filters(self, *args):
        self.filter_entry.set_text('')
        self.show_modified_only.set_active(False)

    def unconfined_toggle(self, *args):
        if not self.finish_init:
            return
        self.wait_mouse()
        if self.enable_unconfined_button.get_active():
            self.dbus.semanage("module -e unconfined")
        else:
            self.dbus.semanage("module -d unconfined")
        self.ready_mouse()

    def permissive_toggle(self, *args):
        if not self.finish_init:
            return
        self.wait_mouse()
        if self.enable_permissive_button.get_active():
            self.dbus.semanage("module -e permissivedomains")
        else:
            self.dbus.semanage("module -d permissivedomains")
        self.ready_mouse()

    def confirmation_close(self, button, *args):
        if len(self.update_treestore) > 0:
            if self.verify(_("You are attempting to close the application without applying your changes.\n    *    To apply changes you have made during this session, click No and click Update.\n    *    To leave the application without applying your changes, click Yes.  All changes that you have made during this session will be lost."), _("Loss of data Dialog")) == Gtk.ResponseType.NO:
                return True
        self.quit()

    def quit(self, *args):
        sys.exit(0)

if __name__ == '__main__':
    start = SELinuxGui()
