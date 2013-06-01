#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import re
from tools import TraceData
from regex import RegexParser

class PathConstraint:
    def __init__(self):
        self.iid = None
        self.kw = 'path'

    def parse(self, args):
        r = re.search('^F, \'(.*)\'(?:, )?([0-9.]+)?$', args)
        dpath = r.group(1) # path
        srate = r.group(2) # optional weight
        if srate is not None:
            srate = float(srate)
        else:
            srate = 1

        data = {}
        data['dpath'] = dpath
        data['srate'] = srate

        # override default samples count if a weight is specified
        # ==> most likely a LB check
        # set samples to 10, we should create a configuration file
        # to avoid hardcoding such values
        if srate > 0 and srate < 1:
            data['samples'] = 10

        return data

    def verify(self, constr, tds, mapping=None, topo=None):
        if len(tds) == 0:
            constr.verifrate = 0
            constr.verified = False
            return

        cnt = 0
        parser = RegexParser()
        fsm = parser.create_fsm(constr.data['dpath']) # create DFA

        for td in tds:
            path = []
            for node in td.path:
                path.append('s'+str(node))
            ret = fsm.process(path) # check path
            if ret is not None:
                cnt += 1

        constr.verifrate = float(cnt)/float(len(tds))
        if constr.check():
            constr.verified = True

    def tostring(self, data):
        return 'F, \'%s\', %f' % (data['dpath'], data['srate'])

def register(iid):
    c = PathConstraint()
    c.iid = iid
    return (c.kw, c)
