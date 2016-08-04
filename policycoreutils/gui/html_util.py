# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2007 Red Hat, Inc.
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


__all__ = [
    'escape_html',
    'unescape_html',
    'html_to_text',

    'html_document',
]

import htmllib
import formatter as Formatter
import string
from types import *
try:
    from io import StringIO
except ImportError:
    from StringIO import StringIO

#------------------------------------------------------------------------------


class TextWriter(Formatter.DumbWriter):

    def __init__(self, file=None, maxcol=80, indent_width=4):
        Formatter.DumbWriter.__init__(self, file, maxcol)
        self.indent_level = 0
        self.indent_width = indent_width
        self._set_indent()

    def _set_indent(self):
        self.indent_col = self.indent_level * self.indent_width
        self.indent = ' ' * self.indent_col

    def new_margin(self, margin, level):
        self.indent_level = level
        self._set_indent()

    def send_label_data(self, data):
        data = data + ' '
        if len(data) > self.indent_col:
            self.send_literal_data(data)
        else:
            offset = self.indent_col - len(data)
            self.send_literal_data(' ' * offset + data)

    def send_flowing_data(self, data):
        if not data:
            return
        atbreak = self.atbreak or data[0] in string.whitespace
        col = self.col
        maxcol = self.maxcol
        write = self.file.write
        col = self.col
        if col == 0:
            write(self.indent)
            col = self.indent_col
        for word in data.split():
            if atbreak:
                if col + len(word) >= maxcol:
                    write('\n' + self.indent)
                    col = self.indent_col
                else:
                    write(' ')
                    col = col + 1
            write(word)
            col = col + len(word)
            atbreak = 1
        self.col = col
        self.atbreak = data[-1] in string.whitespace


class HTMLParserAnchor(htmllib.HTMLParser):

    def __init__(self, formatter, verbose=0):
        htmllib.HTMLParser.__init__(self, formatter, verbose)

    def anchor_bgn(self, href, name, type):
        self.anchor = href

    def anchor_end(self):
        if self.anchor:
            self.handle_data(' (%s) ' % self.anchor)
            self.anchor = None

#------------------------------------------------------------------------------


def escape_html(s):
    if s is None:
        return None
    s = s.replace("&", "&amp;")  # Must be done first!
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("'", "&apos;")
    s = s.replace('"', "&quot;")
    return s


def unescape_html(s):
    if s is None:
        return None
    if '&' not in s:
        return s
    s = s.replace("&lt;", "<")
    s = s.replace("&gt;", ">")
    s = s.replace("&apos;", "'")
    s = s.replace("&quot;", '"')
    s = s.replace("&amp;", "&")  # Must be last
    return s


def html_to_text(html, maxcol=80):
    try:
        buffer = StringIO()
        formatter = Formatter.AbstractFormatter(TextWriter(buffer, maxcol))
        parser = HTMLParserAnchor(formatter)
        parser.feed(html)
        parser.close()
        text = buffer.getvalue()
        buffer.close()
        return text
    except Exception as e:
        log_program.error('cannot convert html to text: %s' % e)
        return None


def html_document(*body_components):
    '''Wrap the body components in a HTML document structure with a valid header.
    Accepts a variable number of arguments of of which canb be:
    * string
    * a sequences of strings (tuple or list).
    * a callable object taking no parameters and returning a string or sequence of strings.
    '''
    head = '<html>\n  <head>\n    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>\n  </head>\n  <body>\n'
    tail = '\n  </body>\n</html>'

    doc = head

    for body_component in body_components:
        if type(body_component) is StringTypes:
            doc += body_component
        elif type(body_component) in [TupleType, ListType]:
            for item in body_component:
                doc += item
        elif callable(body_component):
            result = body_component()
            if type(result) in [TupleType, ListType]:
                for item in result:
                    doc += item
            else:
                doc += result
        else:
            doc += body_component

    doc += tail
    return doc
