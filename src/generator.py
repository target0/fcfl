#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import sys, random
from subprocess import check_output, call
from rulesparser import *
from oflownet import *
from tools import *
from scapy.all import *
import simplejson as json
from optparse import OptionParser
import protocols.manager as pmanager

class Generator:
    """
    Main generator class
    """
    def __init__(self, rules=None, topo=None, mapping=None, cid=None, samples=None):
        self.reqs = None        # Requirements class parsed from the rules
        self.topo = None        # Topology
        self.collectorid = cid  # self-explanatory
        self.mapping = None     # static mapping
        self.samples = samples  # default samples
        self.allpkts = []       # generated packets

        if rules is not None:
            self.reqs = RulesParser().parse(rules)

        if topo is not None:
            self.topo = Topology(topo)

        if mapping is not None:
            self.mapping = Mapping(mapping)

    def set_collector(self, cid):
        self.collectorid = cid

    def to_dl_dst(self, sid, oport):
        """
        Transform a (switch ID, output port) tuple to a 48-bit string
        that will be used as the destination MAC address for packet
        copies transmitted to the collector
        """
        ssid = int(sid) & 0xffff
        soport = int(oport) & 0xffff

        ssid1 = (ssid >> 8) & 0xff
        ssid2 = ssid & 0xff

        sport1 = (soport >> 8) & 0xff
        sport2 = soport & 0xff

        return struct.pack(6*'B', *[0x42, 0x42, ssid1, ssid2, sport1, sport2])

    def hook_switches(self):
        """
        For each switch in the network, modify its flow table to add an mod_dl_dst and
        output action to send truncated packet copies to the collector, with switch ID
        and output encoded in destination MAC address
        """
        for node in self.topo.nodes:
            if not self.topo.is_switch(node):
                continue

            ip, _, port = self.mapping.get_data(node)
            if port == 0:
                sys.stderr.write('Warning: oflow port for s'+str(node)+' is zero, skipping switch\n')
                continue

            ofnet = OFlowNet()
            ofnet.connect(ip, port)
            ofnet.handshake() # wait for HELLO and reply with HELLO (let's be polite :))
            ofnet.dump_flows() # request the content of the flow table
            ofnet.run(OFP_Type.OFPT_STATS_REPLY) # wait until we get the flow entries

            for flow in ofnet.flows:
                ofp_fwst = flow['body']
                ofp_match = flow['match']
                actions = flow['actions']
                tag_actions = []

                # For each output action in the flow, append our mod_dl_dst,output actions
                for act in actions:
                    if act.get('type') == OFP_Action_Type.OFPAT_OUTPUT:
                        # Modify destination MAC
                        ofp_mod_dl_dst = OFP_Action_Mod_Dl_Dst()
                        ofp_mod_dl_dst.set('type', OFP_Action_Type.OFPAT_SET_DL_DST)
                        ofp_mod_dl_dst.set('len', ofp_mod_dl_dst.length)
                        ofp_mod_dl_dst.set('dl_dst', self.to_dl_dst(node, act.get('port')))

                        # Output to collector
                        ofp_act_out = OFP_Action_Output()
                        ofp_act_out.set('type', OFP_Action_Type.OFPAT_OUTPUT)
                        ofp_act_out.set('len', ofp_act_out.length)
                        ofp_act_out.set('port', self.topo.get_port(node, self.collectorid))
                        ofp_act_out.set('max_len', 256)

                        tag_actions.extend([ofp_mod_dl_dst, ofp_act_out])
                actions.extend(tag_actions)

                allacts = ''
                for act in actions:
                    allacts += act.pack()

                # Prepare flow modification command and send it
                ofp_flow_mod = OFP_Flow_Mod()
                ofp_flow_mod.set('cookie', random.getrandbits(64))
                ofp_flow_mod.set('command', OFP_Flow_Mod_Command.OFPFC_MODIFY_STRICT)
                ofp_flow_mod.set('idle_timeout', ofp_fwst.get('idle_timeout'))
                ofp_flow_mod.set('hard_timeout', ofp_fwst.get('hard_timeout'))
                ofp_flow_mod.set('priority', ofp_fwst.get('priority'))
                ofp_flow_mod.set('buffer_id', 0xffffffff)
                ofp_flow_mod.set('out_port', OFP_Port_No.OFPP_NONE)

                body = ofp_match.pack() + ofp_flow_mod.pack() + allacts
                ofp_hdr = OFP_Header(OFP_Type.OFPT_FLOW_MOD, len(body)+8)
                ofnet.send(ofp_hdr.pack()+body)
            ofnet.disconnect()

    def get_packet_prototypes(self, src, dst, proto, gciid, samples):
        """
        Generate packet data from src,dst,proto tuple
        """
        pkts = []

        for snode in src:
            for dnode in dst:
                for i in range(0, samples):
                    print 'Setting packet %d (%s) -> %d (%s)' % (snode, self.mapping.get_mac(snode), dnode, self.mapping.get_mac(dnode))
                    ll = Ether(src=self.mapping.get_mac(snode), dst=self.mapping.get_mac(dnode))

                    if proto is None:
                        proto = "default"
                    inst = pmanager.getinstance(proto.lower())
                    genpkt = inst.build_layers(snode, dnode, gciid, self.mapping, ll)

                    for p in genpkt:
                        pkts.append({'src': snode, 'data':str(p)})
        return pkts

    def generate_packets(self):
        """
            Comparison variables: Hs, Ht, Prot
            Atoms work only for hosts.

            Algorithm:
                1. Determine the set of source hosts
                    ==> No constraint == all hosts
                2. Determine the set of target hosts
                    ==> No constraint == all hosts
                3. Determine the protocol
                    ==> No constraint == default protocol (protocols/default.py)
        """
        for gc in self.reqs.conditions:
            src = []
            dst = []
            proto = None

            if len(gc.constr) > 1:
                raise RuntimeError("More than one constraint for group condition "+str(gc.iid)+", this is not supported at the time.")

            for c in gc.conds:
                if c.source == 'Hs': # source host
                    if c.ctype == Condition.COND_EQUAL:
                        src.append(self.reqs.host_to_node(c.target))
                    elif c.ctype == Condition.COND_ATOM:
                        for h in self.reqs.atoms[c.target]:
                            src.append(self.reqs.host_to_node(h))
                elif c.source == 'Ht': # destination host
                    if c.ctype == Condition.COND_EQUAL:
                        dst.append(self.reqs.host_to_node(c.target))
                    elif c.ctype == Condition.COND_ATOM:
                        for h in self.reqs.atoms[c.target]:
                            dst.append(self.reqs.host_to_node(h))
                elif c.source == 'Prot': # protocol
                    if c.ctype == Condition.COND_EQUAL:
                        proto = c.target
                    elif c.ctype == Condition.COND_ATOM:
                        print 'Warning: unsupported atom condition on protocol, skipping'

            print str(src), str(dst)

            # Samples priority: command line, constraint handler, default
            if self.samples is not None:
                samples = self.samples
            elif 'samples' in gc.constr[0].data:
                samples = gc.constr[0].data['samples']
            else:
                samples = 1

            # Generate packet data
            pkts = self.get_packet_prototypes(src, dst, proto, gc.iid, samples)
            self.allpkts.extend(pkts)
            gc.pkts = pkts

    def send_packets(self, outcon=False):
        """
        Inject the packets in the netwok
        """
        for pkt in self.allpkts:
            src = pkt['src']
            data = pkt['data']
            for s in self.topo.get_edges(src): # inject the packet in all switches connected to the source host
                ip, _, port = self.mapping.get_data(s)
                if port == 0:
                    print "Warning: oflow port for s'+str(node)+' is zero, skipping packet out"
                    continue

                print 'Sending packet from source %d at switch %d IP/port %s/%d' % (src, s, ip, port)

                ofnet = OFlowNet()
                ofnet.connect(ip, port)
                ofnet.handshake()
                oport = OFP_Port_No.OFPP_TABLE
                if outcon:
                    oport = OFP_Port_No.OFPP_CONTROLLER
                ofnet.packet_out(0, data, oport)
                ofnet.disconnect()

    def out_json(self):
        allconds = []
        for gc in self.reqs.conditions:
            e = gc.encode()
#            e['pkts'] = gc.pkts
            allconds.append(e)

        return json.dumps(allconds)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-c", "--collector", dest="cid", metavar="ID", help="Set the collector id")
    parser.add_option("-r", "--rules", dest="rules", metavar="FILE", help="Set the constraints file")
    parser.add_option("-t", "--topology", dest="topo", metavar="FILE", help="Set the topology file")
    parser.add_option("-m", "--mapping", dest="mapping", metavar="FILE", help="Set the mapping file")
    parser.add_option("-k", "--no-hook", dest="hook", action="store_false", default=True, help="Disable flow table modifications")
    parser.add_option("-o", "--out-controller", dest="outcon", action="store_true", default=False, help="Make the switches send the packets to the controller")
    parser.add_option("-s", "--samples", dest="samples", metavar="SAMPLES", help="Samples per test packet, default=1")

    options, args = parser.parse_args()
    if options.cid is None:
        parser.error("Missing collector ID")
    if options.rules is None or options.topo is None or options.mapping is None:
        parser.error("Missing argument. All files must be provided, see -h for help")
    if options.samples is None:
        samples = None
    else:
        samples = int(options.samples)

    g = Generator(cid=int(options.cid), rules=options.rules, topo=options.topo, mapping=options.mapping, samples=samples)

    if options.hook:
        g.hook_switches()
    g.generate_packets()
    g.send_packets(options.outcon)
