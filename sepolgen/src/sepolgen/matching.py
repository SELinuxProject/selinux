# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006 Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
Classes and algorithms for matching requested access to access vectors.
"""

import itertools

from . import access
from . import objectmodel
from . import util


class Match(util.Comparison):
    def __init__(self, interface=None, dist=0):
        self.interface = interface
        self.dist = dist
        self.info_dir_change = False
        # when implementing __eq__ also __hash__ is needed on py2
        # if object is muttable __hash__ should be None
        self.__hash__ = None

    def _compare(self, other, method):
        try:
            a = (self.dist, self.info_dir_change)
            b = (other.dist, other.info_dir_change)
            return method(a, b)
        except (AttributeError, TypeError):
            # trying to compare to foreign type
            return NotImplemented

class MatchList:
    DEFAULT_THRESHOLD = 150
    def __init__(self):
        # Match objects that pass the threshold
        self.children = []
        # Match objects over the threshold
        self.bastards = []
        self.threshold = self.DEFAULT_THRESHOLD
        self.allow_info_dir_change = False
        self.av = None

    def best(self):
        if len(self.children):
            return self.children[0]
        if len(self.bastards):
            return self.bastards[0]
        return None

    def __len__(self):
        # Only return the length of the matches so
        # that this can be used to test if there is
        # a match.
        return len(self.children) + len(self.bastards)

    def __iter__(self):
        return iter(self.children)

    def all(self):
        return itertools.chain(self.children, self.bastards)

    def append(self, match):
        if match.dist <= self.threshold:
            if not match.info_dir_change or self.allow_info_dir_change:
                self.children.append(match)
            else:
                self.bastards.append(match)
        else:
            self.bastards.append(match)

    def sort(self):
        self.children.sort()
        self.bastards.sort()
                

class AccessMatcher:
    def __init__(self, perm_maps=None):
        self.type_penalty = 10
        self.obj_penalty = 10
        if perm_maps:
            self.perm_maps = perm_maps
        else:
            self.perm_maps = objectmodel.PermMappings()
        # We want a change in the information flow direction
        # to be a strong penalty - stronger than access to
        # a few unrelated types.
        self.info_dir_penalty = 100

    def type_distance(self, a, b):
        if a == b or access.is_idparam(b):
            return 0
        else:
            return -self.type_penalty


    def perm_distance(self, av_req, av_prov):
        # First check that we have enough perms
        diff = av_req.perms.difference(av_prov.perms)

        if len(diff) != 0:
            total = self.perm_maps.getdefault_distance(av_req.obj_class, diff)
            return -total
        else:
            diff = av_prov.perms.difference(av_req.perms)
            return self.perm_maps.getdefault_distance(av_req.obj_class, diff)

    def av_distance(self, req, prov):
        """Determine the 'distance' between 2 access vectors.

        This function is used to find an access vector that matches
        a 'required' access. To do this we comput a signed numeric
        value that indicates how close the req access is to the
        'provided' access vector. The closer the value is to 0
        the closer the match, with 0 being an exact match.

        A value over 0 indicates that the prov access vector provides more
        access than the req (in practice, this means that the source type,
        target type, and object class is the same and the perms in prov is
        a superset of those in req.

        A value under 0 indicates that the prov access less - or unrelated
        - access to the req access. A different type or object class will
        result in a very low value.

        The values other than 0 should only be interpreted relative to
        one another - they have no exact meaning and are likely to
        change.

        Params:
          req - [AccessVector] The access that is required. This is the
                access being matched.
          prov - [AccessVector] The access provided. This is the potential
                 match that is being evaluated for req.
        Returns:
          0   : Exact match between the acess vectors.

          < 0 : The prov av does not provide all of the access in req.
                A smaller value indicates that the access is further.

          > 0 : The prov av provides more access than req. The larger
                the value the more access over req.
        """
        # FUTURE - this is _very_ expensive and probably needs some
        # thorough performance work. This version is meant to give
        # meaningful results relatively simply.
        dist = 0

        # Get the difference between the types. The addition is safe
        # here because type_distance only returns 0 or negative.
        dist += self.type_distance(req.src_type, prov.src_type)
        dist += self.type_distance(req.tgt_type, prov.tgt_type)

        # Object class distance
        if req.obj_class != prov.obj_class and not access.is_idparam(prov.obj_class):
            dist -= self.obj_penalty

        # Permission distance

        # If this av doesn't have a matching source type, target type, and object class
        # count all of the permissions against it. Otherwise determine the perm
        # distance and dir.
        if dist < 0:
            pdist = self.perm_maps.getdefault_distance(prov.obj_class, prov.perms)
        else:
            pdist = self.perm_distance(req, prov)

        # Combine the perm and other distance
        if dist < 0:
            if pdist < 0:
                return dist + pdist
            else:
                return dist - pdist
        elif dist >= 0:
            if pdist < 0:
                return pdist - dist
            else:
                return dist + pdist

    def av_set_match(self, av_set, av):
        """

        """
        dist = None

        # Get the distance for each access vector
        for x in av_set:
            tmp = self.av_distance(av, x)
            if dist is None:
                dist = tmp
            elif tmp >= 0:
                if dist >= 0:
                    dist += tmp
                else:
                    dist = tmp + -dist
            else:
                if dist < 0:
                    dist += tmp
                else:
                    dist -= tmp

        # Penalize for information flow - we want to prevent the
        # addition of a write if the requested is read none. We are
        # much less concerned about the reverse.
        av_dir = self.perm_maps.getdefault_direction(av.obj_class, av.perms)

        if av_set.info_dir is None:
            av_set.info_dir = objectmodel.FLOW_NONE
            for x in av_set:
                av_set.info_dir = av_set.info_dir | \
                                  self.perm_maps.getdefault_direction(x.obj_class, x.perms)
        if (av_dir & objectmodel.FLOW_WRITE == 0) and (av_set.info_dir & objectmodel.FLOW_WRITE):
            if dist < 0:
                dist -= self.info_dir_penalty
            else:
                dist += self.info_dir_penalty

        return dist

    def search_ifs(self, ifset, av, match_list):
        match_list.av = av
        for iv in itertools.chain(ifset.tgt_type_all,
                                  ifset.tgt_type_map.get(av.tgt_type, [])):
            if not iv.enabled:
                #print "iv %s not enabled" % iv.name
                continue

            dist = self.av_set_match(iv.access, av)
            if dist >= 0:
                m = Match(iv, dist)
                match_list.append(m)


        match_list.sort()


