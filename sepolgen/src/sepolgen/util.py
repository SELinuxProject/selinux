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

class ConsoleProgressBar:
    def __init__(self, out, steps=100, indicator='#'):
        self.blocks = 0
        self.current = 0
        self.steps = steps
        self.indicator = indicator
        self.out = out
        self.done = False

    def start(self, message=None):
        self.done = False
        if message:
            self.out.write('\n%s:\n' % message)
        self.out.write('%--10---20---30---40---50---60---70---80---90--100\n')

    def step(self, n=1):
        self.current += n

        old = self.blocks
        self.blocks = int(round(self.current / float(self.steps) * 100) / 2)

        if self.blocks > 50:
            self.blocks = 50

        new = self.blocks - old

        self.out.write(self.indicator * new)
        self.out.flush()

        if self.blocks == 50 and not self.done:
            self.done = True
            self.out.write("\n")

def set_to_list(s):
    l = []
    l.extend(s)
    return l

def first(s, sorted=False):
    """
    Return the first element of a set.

    It sometimes useful to return the first element from a set but,
    because sets are not indexable, this is rather hard. This function
    will return the first element from a set. If sorted is True, then
    the set will first be sorted (making this an expensive operation).
    Otherwise a random element will be returned (as sets are not ordered).
    """
    if not len(s):
        raise IndexError("empty containter")
    
    if sorted:
        l = set_to_list(s)
        l.sort()
        return l[0]
    else:
        for x in s:
            return x

if __name__ == "__main__":
    import sys
    import time
    p = ConsoleProgressBar(sys.stdout, steps=999)
    p.start("computing pi")
    for i in range(999):
        p.step()
        time.sleep(0.001)

