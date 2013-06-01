#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

from scapy.all import *
import random

class SSHProtocol:
    def __init__(self):
        self.proto = 'ssh'

    def build_layers(self, snode, dnode, gciid, mapping, linklayer):
        ip = IP(src=mapping.get_ip(snode), dst=mapping.get_ip(dnode), id=gciid)
        ul = TCP(dport=22, sport=random.getrandbits(16), chksum=0x4242)
        return linklayer/ip/ul

def register():
    p = SSHProtocol()
    return (p.proto, p)
