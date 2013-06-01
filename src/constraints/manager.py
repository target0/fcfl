#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys

class ConstraintManager:
    def __init__(self):
        self.iid = 0
        self.kw = {}
        self.ids = {}

    def modregister(self, call):
        self.iid += 1
        kw, inst = call(self.iid)
        self.kw[kw] = inst
        self.ids[self.iid] = inst

    def getinstance(self, kw=None, id=None):
        if kw is not None:
            return self.kw[kw]
        if id is not None:
            return self.ids[id]

def _import_star(m):
    mod = __import__(m, globals(), locals())
    for k,v in mod.__dict__.iteritems():
        globals()[k] = v
    return mod

_inst = ConstraintManager()
getinstance = _inst.getinstance

kws = ["allow", "delay", "deny", "path"]

for _k in kws:
    try:
        mod = _import_star(_k)
    except Exception,e:
        sys.stderr.write('Failed to import keyword %s: %s\n' % (_k, e))
    _inst.modregister(mod.register)
