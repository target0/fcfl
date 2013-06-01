#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

from scapy.all import *
import random

class ICMPProtocol:
    def __init__(self):
        self.proto = 'icmp'

    def build_layers(self, snode, dnode, gciid, mapping, linklayer):
        ip = IP(src=mapping.get_ip(snode), dst=mapping.get_ip(dnode), id=gciid)
        ul = ICMP(type=8, id=random.getrandbits(16), chksum=0x4242)
        return linklayer/ip/ul

def register():
    p = ICMPProtocol()
    return (p.proto, p)
