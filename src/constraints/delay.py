#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import re
from tools import TraceData

class DelayConstraint:
    def __init__(self):
        self.iid = None
        self.kw = 'delay'

    def parse(self, args):
        r = re.search('^F, ([0-9.]+)$', args)
        d = float(r.group(1))
        return {'delay': d}

    def verify(self, constr, tds, mapping=None, topo=None):
        # Constraint cannot verify if there is no trace
        if len(tds) == 0:
            constr.verifrate = 0
            constr.verified = False
            return

        cnt = 0
        for td in tds:
            if td.delay <= constr.data['delay']:
                cnt += 1

        constr.verifrate = float(cnt)/float(len(tds))
        if constr.check():
            constr.verified = True

    def tostring(self, data):
        return 'F, %f' % (data)

def register(iid):
    c = DelayConstraint()
    c.iid = iid
    return (c.kw, c)
