# Copyright (C) 2012 Red Hat
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
import sys


def usage(parser, msg):
    parser.print_help()

    sys.stderr.write("\n%s\n" % msg)
    sys.stderr.flush()
    sys.exit(1)


def expand_attribute(attribute):
    try:
        return list(next(sepolicy.info(sepolicy.ATTRIBUTE, attribute))["types"])
    except StopIteration:
        return [attribute]


def get_types(src, tclass, perm):
    allows = sepolicy.search([sepolicy.ALLOW], {sepolicy.SOURCE: src, sepolicy.CLASS: tclass, sepolicy.PERMS: perm})
    if not allows:
        raise ValueError("The %s type is not allowed to %s any types" % (src, ",".join(perm)))

    tlist = []
    for l in map(lambda y: y[sepolicy.TARGET], filter(lambda x: set(perm).issubset(x[sepolicy.PERMS]), allows)):
        tlist = tlist + expand_attribute(l)
    return tlist
