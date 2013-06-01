#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys

class ProtocolManager:
    def __init__(self):
        self.protos = {}

    def modregister(self, call):
        proto, inst = call()
        self.protos[proto] = inst

    def getinstance(self, proto):
        return self.protos[proto]

def _import_star(m):
    mod = __import__(m, globals(), locals())
    for k,v in mod.__dict__.iteritems():
        globals()[k] = v
    return mod

_inst = ProtocolManager()
getinstance = _inst.getinstance

protos = ["default", "icmp", "http", "ssh", "mail"]

for _k in protos:
    try:
        mod = _import_star(_k)
    except Exception,e:
        sys.stderr.write('Failed to import protocol %s: %s\n' % (_k, e))
    _inst.modregister(mod.register)
