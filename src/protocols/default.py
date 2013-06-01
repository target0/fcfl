#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

from scapy.all import *
import random

class DefaultProtocol:
    """
    Default protocol used when no constraint is defined on the protocol
    """
    def __init__(self):
        self.proto = 'default'

    def build_layers(self, snode, dnode, gciid, mapping, linklayer):
        ip = IP(src=mapping.get_ip(snode), dst=mapping.get_ip(dnode), id=gciid)
        ul = UDP(dport=64242, sport=random.getrandbits(16), chksum=0x4242)
        return linklayer/ip/ul

def register():
    p = DefaultProtocol()
    return (p.proto, p)
