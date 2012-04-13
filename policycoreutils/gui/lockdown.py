#!/usr/bin/python
#
# lockdown.py - GUI for Booleans page in system-config-securitylevel
#
# Dan Walsh <dwalsh@redhat.com>
#
# Copyright 2008 Red Hat, Inc.
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
import signal
import string
import gtk
import gtk.glade
import os
import gobject
import gnome
import sys
import selinux
import seobject
import webkit
import commands
import tempfile

from html_util import *

gnome.program_init("SELinux Boolean Lockdown Tool", "5")

INSTALLPATH='/usr/share/system-config-selinux'
sys.path.append(INSTALLPATH)

##
## I18N
##
PROGNAME="policycoreutils"

import gettext
gettext.bindtextdomain(PROGNAME, "/usr/share/locale")
gettext.textdomain(PROGNAME)
try:
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    unicode=False,
                    codeset = 'utf-8')
except IOError:
    import __builtin__
    __builtin__.__dict__['_'] = unicode

from glob import fnmatch

STATUS=(_("Disable"), _("Enable"), _("Default"))
DISABLE = 0
ENABLE = 1
DEFAULT = 2

def idle_func():
    while gtk.events_pending():
        gtk.main_iteration()

def td_fmt(val):
    return '<td>%s</td>' % val

tr_fmt = '<tr>%s</tr>\n'

p_fmt = '<p>%s\n'

##
## Pull in the Glade file
##
if os.access("system-config-selinux.glade", os.F_OK):
    xml = gtk.glade.XML ("lockdown.glade", domain=PROGNAME)
else:
    xml = gtk.glade.XML ("/usr/share/system-config-selinux/lockdown.glade", domain=PROGNAME)
BOOLEAN = 0
class booleanWindow:
    def __init__(self):
        self.tabs=[]
        self.xml = xml
        xml.signal_connect("on_cancel_clicked", self.cancel)
        xml.signal_connect("on_forward_clicked", self.forward)
        xml.signal_connect("on_previous_clicked", self.previous)
        xml.signal_connect("on_save_clicked", self.save)
        xml.signal_connect("on_apply_clicked", self.apply)
        self.xml = xml
        self.mainWindow = self.xml.get_widget("mainWindow")
        self.forwardbutton = self.xml.get_widget("forwardButton")
        self.window = self.xml.get_widget("mainWindow").get_root_window()
        self.busy_cursor = gtk.gdk.Cursor(gtk.gdk.WATCH)
        self.ready_cursor = gtk.gdk.Cursor(gtk.gdk.LEFT_PTR)
        self.radiobox = self.xml.get_widget("radiobox")
        self.savebox = self.xml.get_widget("savebox")
        self.file_dialog = self.xml.get_widget("filechooserdialog")
        self.vbox = self.xml.get_widget("vbox")
        self.enable_radiobutton = self.xml.get_widget("enable_radiobutton")
        self.enable_radiobutton.connect("toggled", self.toggled)
        self.disable_radiobutton = self.xml.get_widget("disable_radiobutton")
        self.disable_radiobutton.connect("toggled", self.toggled)
        self.default_radiobutton = self.xml.get_widget("default_radiobutton")
        self.default_radiobutton.connect("toggled", self.toggled)
        self.html_scrolledwindow = self.xml.get_widget("html_scrolledwindow")
        self.view = xml.get_widget("booleanView")
        self.view.get_selection().connect("changed", self.itemSelected)

        self.store = gtk.TreeStore(gobject.TYPE_STRING)
        self.view.set_model(self.store)

        col = gtk.TreeViewColumn("Boolean", gtk.CellRendererText(), text=BOOLEAN)
        col.set_sort_column_id(BOOLEAN)
        col.set_resizable(True)
        self.view.append_column(col)

        self.html_view = self.create_htmlview(self.html_scrolledwindow)
        self.load()
        self.view.get_selection().select_path ((0,))

    def create_htmlview(self, container):
        view = webkit.WebView()
        container.add(view)
        return (view)

    def wait(self):
        self.window.set_cursor(self.busy_cursor)
        idle_func()

    def ready(self):
        self.window.set_cursor(self.ready_cursor)
        idle_func()

    def load(self):
        self.store.clear()
        self.booleans = seobject.booleanRecords()
        booleansList = self.booleans.get_all(0)
        self.booldict = {}
        for name in booleansList:
            cat = self.booleans.get_category(name)
            if cat not in self.booldict:
                self.booldict[cat] = {}

            rec = booleansList[name]
            self.booldict[cat][name]= [rec[2], self.booleans.get_desc(name)]

        cats = self.booldict.keys()
        cats.sort()

        citer = self.store.append(None)
        self.store.set_value(citer, BOOLEAN, "Begin")
        for cat in  cats:
            citer = self.store.append(None)
            self.store.set_value(citer, BOOLEAN, cat)
            bools = self.booldict[cat].keys()
            for bool in  bools:
                biter = self.store.append(citer)
                self.store.set_value(biter, BOOLEAN, bool)
            biter = self.store.append(citer)
            self.store.set_value(biter, BOOLEAN, "Finish")
        citer = self.store.append(None)
        self.store.set_value(citer, BOOLEAN, "Finish")

    def on_about_activate(self, args):
        dlg = xml.get_widget ("aboutWindow")
        dlg.run ()
        dlg.hide ()

    def cancel(self, args):
        gtk.main_quit()

    def error(self, message):
        dlg = gtk.MessageDialog(None, 0, gtk.MESSAGE_ERROR,
                                gtk.BUTTONS_CLOSE,
                                message)
        dlg.set_position(gtk.WIN_POS_MOUSE)
        dlg.show_all()
        dlg.run()
        dlg.destroy()

    def __out(self):
        out = ''
        for c in self.booldict.keys():
            for b in self.booldict[c]:
                out += "%s=%s\n" % (b, self.booldict[c][b][0])
        return out

    def save(self, args):
        self.file_dialog.set_action(gtk.FILE_CHOOSER_ACTION_SAVE)
        rc = self.file_dialog.run()
        self.file_dialog.hide()
        if rc == gtk.RESPONSE_OK:
            try:
                fd = open(self.file_dialog.get_filename(), "w")
                fd.write(self.__out())
                fd.close()

            except IOError, e:
                self.error(e)

    def apply(self, args):
        fd = tempfile.NamedTemporaryFile(dir = "/var/lib/selinux")
        fd.write(self.__out())
        fd.flush()
        self.wait()
        rc, err = commands.getstatusoutput("semanage boolean -m -F %s" % fd.name)
        self.ready()
        fd.close()
        if rc != 0:
            self.error(err)

    def forward(self, args):
        selection = self.view.get_selection()
        store, iter = selection.get_selected()
        if self.store.iter_has_child(iter):
            store, rows = selection.get_selected_rows()
            self.view.expand_to_path(rows[0])
            niter = self.store.iter_nth_child(iter, 0)
        else:
            niter = store.iter_next(iter)

        if niter == None:
            piter = self.store.iter_parent(iter)
            if piter == None:
                return
            niter = store.iter_next(piter)

        if niter != None:
            selection.select_iter(niter)
            store, rows = selection.get_selected_rows()
            self.view.scroll_to_cell(rows[0])
        else:
            print "Finish"

    def toggled(self, button):
        if button.get_active() == False:
            return
        if self.cat == None:
            return
        if self.disable_radiobutton == button:
            self.booldict[self.cat][self.name][0] = DISABLE
        if self.enable_radiobutton == button:
            self.booldict[self.cat][self.name][0] = ENABLE
        if self.default_radiobutton == button:
            self.booldict[self.cat][self.name][0] = DEFAULT

    def previous(self, args):
        selection = self.view.get_selection()
        store, iter = selection.get_selected()
        store, rows = selection.get_selected_rows()
        row = rows[0]
        if len(row) == 1 or self.store.iter_has_child(iter):
            if row[0] == 0:
                return
            nrow = row[0] - 1
            iter = self.store.get_iter((nrow,))
            if self.store.iter_has_child(iter):
                self.view.expand_to_path((nrow,))
                n = store.iter_n_children(iter) -1
                piter = store.iter_nth_child(iter, n)
            else:
                piter = iter
        else:
            if row[1] == 0:
                piter = self.store.iter_parent(iter)
            else:
                r0 = row[0]
                r1 = row[1] - 1
                piter = self.store.get_iter((r0,r1))
        if piter != None:
            selection.select_iter(piter)
            store, rows = selection.get_selected_rows()
            self.view.scroll_to_cell(rows[0])
        else:
            print "Finish"

    def html_cat(self, cat):
        html = ""
        row = td_fmt(_("<b>Boolean</b>")) + td_fmt(_("<b>Description</b>")) + td_fmt(_("<b>Status</b>"))
        html += tr_fmt % row

        for b in self.booldict[cat]:
            row = td_fmt(b) + td_fmt(self.booleans.get_desc(b)) + td_fmt(STATUS[self.booldict[cat][b][0]])
            html += tr_fmt % row
        return html

    def html_table(self, title, body):
        html = self.html_head(title)
        html += '<table width="100%" cellspacing="1" cellpadding="2">\n'
        html += body
        html += '</table>'
        return html

    def html_head(self, val):
        # Wrap entire alert in one table
        # 1st table: primary Information

        html = '<b>%s</b>\n\n\n' % val
        return html

    def html_all(self):
        html = ""
        cats = self.booldict.keys()
        cats.sort()
        for cat in  cats:
            html += self.html_table((_("Category: %s <br>") % cat), self.html_cat(cat))
        return html

    def itemSelected(self, selection):
        store, iter = selection.get_selected()
        if iter == None:
            return

        piter = self.store.iter_parent(iter)
        if piter != None:
            self.cat =  store.get_value(piter, BOOLEAN)
        else:
            self.cat =  None

        self.name =  store.get_value(iter, BOOLEAN)

        html = ''

        self.radiobox.hide()
        self.savebox.hide()

        if self.name == _("Begin"):
            html += self.html_head(_("Welcome to the SELinux Lockdown Tool.<br> <br>This tool can be used to lockdown SELinux booleans.The tool will generate a configuration file which can be used to lockdown this system or other SELinux systems.<br>"))
            html += self.html_all()
        else:
            if self.name == _("Finish"):
                if self.cat != None:
                    html += self.html_head(_("Category %s booleans completed <br><br>") % self.cat)
                    html += self.html_table(_("Current settings:<br><br>"), self.html_cat(self.cat))
                else:
                    html += self.html_head(_("Finish: <br><br>"))
                    html += self.html_all()
                    self.savebox.show()
            else:
                if self.store.iter_has_child(iter):
                    html += self.html_table(_("Category: %s<br><br>Current Settings<br><br>") % self.name, self.html_cat(self.name))
                else:
                    self.radiobox.show()
                    html += self.html_table(_("Boolean:   %s<br><br>") % self.name, tr_fmt % td_fmt(self.booleans.get_desc(self.name)))
                    if self.booldict[self.cat][self.name][0] == ENABLE:
                        self.enable_radiobutton.set_active(True)
                    if self.booldict[self.cat][self.name][0] == DISABLE:
                        self.disable_radiobutton.set_active(True)
                    if self.booldict[self.cat][self.name][0] == DEFAULT:
                        self.default_radiobutton.set_active(True)
        html_doc= html_document(html)

        self.html_view.load_html_string(html, "")

    def stand_alone(self):
        desktopName = _("Lockdown SELinux Booleans")

        self.mainWindow.connect("destroy", self.cancel)

        self.mainWindow.show_all()
        self.radiobox.hide()
        self.savebox.hide()
        gtk.main()

if __name__ == "__main__":
    signal.signal (signal.SIGINT, signal.SIG_DFL)

    app = booleanWindow()
    app.stand_alone()
