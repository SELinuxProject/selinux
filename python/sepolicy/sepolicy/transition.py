# Copyright (C) 2011 Red Hat
# see file 'COPYING' for use and warranty information
#
# setrans is a tool for analyzing process transitions in SELinux policy
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
#
import sepolicy
__all__ = ['setrans']


def _entrypoint(src):
    trans = sepolicy.search([sepolicy.ALLOW], {sepolicy.SOURCE: src})
    return map(lambda y: y[sepolicy.TARGET], filter(lambda x: "entrypoint" in x[sepolicy.PERMS], trans))


def _get_trans(src):
    src_list = [src] + list(filter(lambda x: x['name'] == src, sepolicy.get_all_types_info()))[0]['attributes']
    trans_list = list(filter(lambda x: x['source'] in src_list and x['class'] == 'process', sepolicy.get_all_transitions()))
    return trans_list


class setrans:

    def __init__(self, source, dest=None):
        self.seen = []
        self.sdict = {}
        self.source = source
        self.dest = dest
        self._process(self.source)

    def _process(self, source):
        if source in self.sdict:
            return self.sdict[source]
        self.sdict[source] = {}
        trans = _get_trans(source)
        if not trans:
            return
        self.sdict[source]["name"] = source
        if not self.dest:
            self.sdict[source]["map"] = trans
        else:
            self.sdict[source]["map"] = list(map(lambda y: y, filter(lambda x: x["transtype"] == self.dest, trans)))
            self.sdict[source]["child"] = list(map(lambda y: y["transtype"], filter(lambda x: x["transtype"] not in [self.dest, source], trans)))
            for s in self.sdict[source]["child"]:
                self._process(s)

    def out(self, name, header=""):
        buf = ""
        if name in self.seen:
            return buf
        self.seen.append(name)

        if "map" in self.sdict[name]:
            for t in self.sdict[name]["map"]:
                cond = sepolicy.get_conditionals(t["source"], t["transtype"], "process", ["transition"])
                if cond:
                    buf += "%s%s @ %s --> %s %s\n" % (header, t["source"], t["target"], t["transtype"], sepolicy.get_conditionals_format_text(cond))
                else:
                    buf += "%s%s @ %s --> %s\n" % (header, t["source"], t["target"], t["transtype"])

        if "child" in self.sdict[name]:
            for x in self.sdict[name]["child"]:
                buf += self.out(x, "%s%s ... " % (header, name))
        return buf

    def output(self):
        self.seen = []
        print(self.out(self.source))
