#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import re
from tools import TraceData, Mapping, Topology

class DenyConstraint:
    def __init__(self):
        self.iid = None
        self.kw = 'deny'

    def parse(self, args):
        return {}

    def verify(self, constr, tds, mapping, topo):
        # Constraint is verified if there is no trace (special case)
        if len(tds) == 0:
            constr.verifrate = 1
            constr.verified = True
            return

        # Same check as allow constr
        cnt = 0
        for td in tds:
            snode = mapping.get_node_from_ip(td.src)
            dnode = mapping.get_node_from_ip(td.dst)
            if snode is None or dnode is None:
                sys.stderr.write('Warning: verify_allow(): source or destination IP is not mapped\n')
                continue
            if topo.is_connected(snode, td.path[0]) and topo.is_connected(dnode, td.path[-1]):
                cnt += 1
        # Reverse
        constr.verifrate = 1.0-(float(cnt)/float(len(tds)))
        if constr.check():
            constr.verified = True

    def tostring(self, data):
        return 'F'

def register(iid):
    c = DenyConstraint()
    c.iid = iid
    return (c.kw, c)
