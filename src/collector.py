#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys, time
from scapy.all import *
import simplejson as json
from optparse import OptionParser

class Collector:
    """
    Main collector class
    """
    def __init__(self):
        self.pkts = [] # collected traces

    def callback(self, pkt):
        """ Just store the packet with ts in order to minimize processing time """
        self.pkts.append((time.time(), pkt))

    def collect(self, tm):
        trace = []
        sniff(filter="not arp", timeout=tm, prn=self.callback)

        for ts, p in self.pkts:
            s = p.sprintf("{Ether:%Ether.dst%}/{IP:%IP.src%;%IP.dst%;%IP.id%;%IP.proto%}")
            data = s.split('/')
            mac = data[0].split(":")

            # Extract data from destination MAC
            b1 = ((int(mac[0], base=16) & 0xff) << 8 | (int(mac[1], base=16) & 0xff)) & 0xffff  # magic
            b2 = ((int(mac[2], base=16) & 0xff) << 8 | (int(mac[3], base=16) & 0xff)) & 0xffff  # switch ID
            b3 = ((int(mac[4], base=16) & 0xff) << 8 | (int(mac[5], base=16) & 0xff)) & 0xffff  # output port

            if b1 != 0x4242:
                sys.stderr.write('Not a postcard, skipping packet\n')
                continue

            if b3 >= 0xff00:
                sys.stderr.write('Outport > MAX_PORT, probably sent to controller, skipping packet\n')
                continue

            ipdata = data[1].split(";")
            ipsrc = ipdata[0]
            ipdst = ipdata[1]
            ipid = int(ipdata[2])
            proto = ipdata[3]

            # Extract packet ID according to L3 protocol
            if proto == "icmp":
                chksum = p.sprintf("{ICMP:%ICMP.chksum%}")
                seq = p.sprintf("{ICMP:%ICMP.seq%}")
                if seq is None:
                    continue
                pktid = int(seq)
            elif proto == "udp":
                chksum = p.sprintf("{UDP:%UDP.chksum%}")
                pktid = int(p.sprintf("{UDP:%r,UDP.sport%}"))
            elif proto == "tcp":
                chksum = p.sprintf("{TCP:%TCP.chksum%}")
                pktid = int(p.sprintf("{TCP:%r,TCP.sport%}"))
            else:
                sys.stderr.write('Unknown protocol '+proto+', skipping packet\n')
                continue

            if chksum[:2] == '0x':
                chksum = int(chksum[2:], base=16)
            else:
                sys.stderr.write('Unknown checksum format '+chksum+'\n')
                continue

            if chksum != 0x4242:
                sys.stderr.write('Checksum does not match magic value, skipping packet\n')
                continue

            trace.append({'id': pktid, 'ts': ts, 'src': ipsrc, 'dst': ipdst, 'gcid': ipid, 'proto': proto, 'switch': b2, 'outport': b3})

        return trace

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-t", "--timeout", dest="timeout", metavar="SECONDS", help="collection timeout")
    options, args = parser.parse_args()

    timeout = 5
    if options.timeout is not None:
        timeout = int(options.timeout)

    c = Collector()
    trace = c.collect(timeout)
    print json.dumps(trace)
