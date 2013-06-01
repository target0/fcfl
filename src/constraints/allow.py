#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import re
from tools import TraceData, Mapping, Topology

class AllowConstraint:
    def __init__(self):
        self.iid = None
        self.kw = 'allow'

    def parse(self, args):
        return {}

    def verify(self, constr, tds, mapping, topo):
        # If there is no trace, the constraint cannot verify
        if len(tds) == 0:
            constr.verifrate = 0
            constr.verified = False
            return

        cnt = 0
        for td in tds:
            snode = mapping.get_node_from_ip(td.src)
            dnode = mapping.get_node_from_ip(td.dst)
            if snode is None or dnode is None:
                sys.stderr.write('Warning: verify_allow(): source or destination IP is not mapped\n')
                continue
            # Constraint is verified is source is connected to first switch
            # and destination is connected to last switch
            if topo.is_connected(snode, td.path[0]) and topo.is_connected(dnode, td.path[-1]):
                cnt += 1
        constr.verifrate = float(cnt)/float(len(tds))
        print 'Matched count %d vs len %d' % (cnt, len(tds))
        if constr.check():
            constr.verified = True

    def tostring(self, data):
        return 'F'

def register(iid):
    c = AllowConstraint()
    c.iid = iid
    return (c.kw, c)
