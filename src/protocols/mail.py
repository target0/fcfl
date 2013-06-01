#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

from scapy.all import *
import random

class MailProtocol:
    def __init__(self):
        self.proto = 'mail'

    def build_layers(self, snode, dnode, gciid, mapping, linklayer):
        ip = IP(src=mapping.get_ip(snode), dst=mapping.get_ip(dnode), id=gciid)
        # smtp, smtps, imap, imap3, imaps, submission
        ul = TCP(dport=[25, 143, 220, 465, 587, 993], sport=random.getrandbits(16), chksum=0x4242)
        return linklayer/ip/ul

def register():
    p = MailProtocol()
    return (p.proto, p)
