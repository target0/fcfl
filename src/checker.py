#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys
from rulesparser import *
from regex import *
from tools import *
import simplejson as json
import constraints.manager as cmanager

class Checker:
    """
    Main checker class.
    """
    def __init__(self, rules=None, topo=None, mapping=None, trace=None):
        self.reqs = None        # Requirements class, generated from the rules
        self.rawtrace = None    # collected traces
        self.trace = {}         # reconstructed packets
        self.gc = {}            # grouped conditions
        self.mapping = None     # static mapping
        self.topo = None        # topology

        if rules is not None:
            self.reqs = RulesParser().parse(rules)

        if topo is not None:
            self.topo = Topology(topo)

        if mapping is not None:
            self.mapping = Mapping(mapping)

        if trace is not None:
            self.load_trace(trace)

    def load_trace(self, fname):
        f = open(fname, 'r')
        data = f.readlines()
        f.close()

        self.rawtrace = json.loads("".join(data))

    def reassemble_packets(self):
        """
        Reconstruct packets from their collected traces
        """
        for pkt in self.rawtrace:
            print 'Processing packet '+str(pkt)
            if pkt['id'] not in self.trace:
                td = TraceData(pkt['src'], pkt['dst'], pkt['gcid'], pktid=pkt['id']) # create a new packet
                td.path.append(pkt['switch']) # append path
                td.ts = 0
                td.lastts = pkt['ts']
                self.trace[pkt['id']] = td
            else:
                td = self.trace[pkt['id']]
                td.path.append(pkt['switch'])
                td.ts += pkt['ts'] - td.lastts # recompute delay
                td.lastts = pkt['ts']

        for pktid in self.trace:
            td = self.trace[pktid]
            td.delay = td.ts*1000 # set delay to milliseconds
            if td.gcid not in self.gc: # dispatch reconstructed packets to their belonging grouped condition
                self.gc[td.gcid] = [td]
            else:
                self.gc[td.gcid].append(td)

    def verify(self):
        """
        Verify all constraints
        """
        for gc in self.reqs.conditions:
            if gc.iid not in self.gc:
                data = []
            else:
                data = self.gc[gc.iid]
            for constr in gc.constr:
                inst = cmanager.getinstance(id=constr.ctype) # fetch constraint instance
                inst.verify(constr, data, mapping=self.mapping, topo=self.topo) # actual verification

        """
        Iterate over groups and check if they are verified.
        A group is verified if one and only one priority level is verified.
        A level is verified if any of its constraint is verified.
        """
        for grpid in self.reqs.grpconstraints:
            grp = self.reqs.grpconstraints[grpid]
            prios = {}
            for constr in grp.constraints:
                if constr.prio not in prios:
                    prios[constr.prio] = False
                if constr.verified:
                    prios[constr.prio] = True

            cnt = 0
            for p in prios:
                if prios[p]:
                    cnt += 1

            if cnt == 1:
                grp.verified = True

        # Compute number of unsatisfied constraints
        cnt = 0
        for constr in self.reqs.constraints:
            if constr.ctype != Constraint.CONSTR_GROUP and constr.grp == 0 and not constr.verified:
                cnt += 1
            elif constr.ctype == Constraint.CONSTR_GROUP and not constr.verified:
                cnt += 1

        return cnt

def dump_constr(constr):
    m = 'UNMATCHED'
    if constr.verified:
        m = 'MATCHED'
    print str(constr)+' ----> '+m+' (success: %f, threshold: %f)' % (constr.verifrate, constr.srate)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print 'Usage: %s <rules file> <topology file> <mapping file> <trace file>' % (sys.argv[0])
        sys.exit(-1)

    c = Checker(rules=sys.argv[1], topo=sys.argv[2], mapping=sys.argv[3], trace=sys.argv[4])
    c.reassemble_packets()

    for t in c.trace:
        print t

    cnt = c.verify()
    print 'There are %d unmatched constraints.' % (cnt)

    for constr in c.reqs.constraints:
        if constr.ctype == Constraint.CONSTR_GROUP:
            for c2 in constr.constraints:
                dump_constr(c2)
        else:
            dump_constr(constr)
