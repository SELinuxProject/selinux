#! /usr/bin/python -Es
# Copyright (C) 2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# setrans is a tool for analyzing process transistions in SELinux policy
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


def get_types(src, tclass, perm, check_bools=False):
    allows = sepolicy.search([sepolicy.ALLOW], {sepolicy.SOURCE: src, sepolicy.CLASS: tclass, sepolicy.PERMS: perm})
    nlist = []
    if allows:
        for i in map(lambda y: y[sepolicy.TARGET], filter(lambda x: set(perm).issubset(x[sepolicy.PERMS]) and (not check_bools or x["enabled"]), allows)):
            if i not in nlist:
                nlist.append(i)
    return nlist


def get_network_connect(src, protocol, perm, check_bools=False):
    portrecs, portrecsbynum = sepolicy.gen_port_dict()
    d = {}
    tlist = get_types(src, "%s_socket" % protocol, [perm], check_bools)
    if len(tlist) > 0:
        d[(src, protocol, perm)] = []
        for i in tlist:
            if i == "ephemeral_port_type":
                if "unreserved_port_type" in tlist:
                    continue
                i = "ephemeral_port_t"
            if i == "unreserved_port_t":
                if "unreserved_port_type" in tlist:
                    continue
                if "port_t" in tlist:
                    continue
            if i == "port_t":
                d[(src, protocol, perm)].append((i, ["all ports with out defined types"]))
            if i == "port_type":
                d[(src, protocol, perm)].append((i, ["all ports"]))
            elif i == "unreserved_port_type":
                d[(src, protocol, perm)].append((i, ["all ports > 1024"]))
            elif i == "reserved_port_type":
                d[(src, protocol, perm)].append((i, ["all ports < 1024"]))
            elif i == "rpc_port_type":
                d[(src, protocol, perm)].append((i, ["all ports > 500 and  < 1024"]))
            else:
                try:
                    d[(src, protocol, perm)].append((i, portrecs[(i, protocol)]))
                except KeyError:
                    pass
    return d
