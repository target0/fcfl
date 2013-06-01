#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

import struct, socket, re, random

"""
Partial implementation of OpenFlow 1.0 protocol
"""

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

OFP_ETH_ALEN = 6

OFP_Type =  enum('OFPT_HELLO',
                'OFPT_ERROR',
                'OFPT_ECHO_REQUEST',
                'OFPT_ECHO_REPLY',
                'OFPT_VENDOR',
                # Switch conf
                'OFPT_FEATURES_REQUEST',
                'OFPT_FEATURES_REPLY',
                'OFPT_GET_CONFIG_REQUEST',
                'OFPT_GET_CONFIG_REPLY',
                'OFPT_SET_CONFIG',
                # Async
                'OFPT_PACKET_IN',
                'OFPT_FLOW_REMOVED',
                'OFPT_PORT_STATUS',
                # Controller command
                'OFPT_PACKET_OUT',
                'OFPT_FLOW_MOD',
                'OFPT_PORT_MOD',
                # Statistics
                'OFPT_STATS_REQUEST',
                'OFPT_STATS_REPLY',
                # Barrier
                'OFPT_BARRIER_REQUEST',
                'OFPT_BARRIER_REPLY',
                # Queue conf
                'OFPT_QUEUE_GET_CONFIG_REQUEST',
                'OFPT_QUEUE_GET_CONFIG_REPLY')

OFP_Port_Config =  enum(OFPPC_PORT_DOWN     = 1 << 0,
                        OFPPC_NO_STP        = 1 << 1,
                        OFPPC_NO_RECV       = 1 << 2,
                        OFPPC_NO_RECV_STP   = 1 << 3,
                        OFPPC_NO_FLOOD      = 1 << 4,
                        OFPPC_NO_FWD        = 1 << 5,
                        OFPPC_NO_PACKET_IN  = 1 << 6)

OFP_Port_state =   enum(OFPPS_LINK_DOWN = 1 << 0,
                        OFPPS_BLOCKED   = 1 << 1,
                        OFPPS_LIVE      = 1 << 2)

OFP_Port_No =      enum(OFPP_MAX        = 0xff00,
                        OFPP_IN_PORT    = 0xfff8,
                        OFPP_TABLE      = 0xfff9,
                        OFPP_NORMAL     = 0xfffa,
                        OFPP_FLOOD      = 0xfffb,
                        OFPP_ALL        = 0xfffc,
                        OFPP_CONTROLLER = 0xfffd,
                        OFPP_LOCAL      = 0xfffe,
                        OFPP_NONE       = 0xffff)

OFP_Action_Type =  enum('OFPAT_OUTPUT',
                        'OFPAT_SET_VLAN_VID',
                        'OFPAT_SET_VLAN_PCP',
                        'OFPAT_STRIP_VLAN',
                        'OFPAT_SET_DL_SRC',
                        'OFPAT_SET_DL_DST',
                        'OFPAT_SET_NW_SRC',
                        'OFPAT_SET_NW_DST',
                        'OFPAT_SET_NW_TOS',
                        'OFPAT_SET_TP_SRC',
                        'OFPAT_SET_TP_DST',
                        'OFPAT_ENQUEUE',
                        OFPAT_VENDOR = 0xffff)

OFP_Flow_Mod_Command = enum('OFPFC_ADD',
                            'OFPFC_MODIFY',
                            'OFPFC_MODIFY_STRICT',
                            'OFPFC_DELETE',
                            'OFPFC_DELETE_STRICT')

OFP_Stats_Types =  enum('OFPST_DESC',
                        'OFPST_FLOW',
                        'OFPST_AGGREGATE',
                        'OFPST_TABLE',
                        'OFPST_PORT',
                        'OFPST_QUEUE',
                        OFPST_VENDOR = 0xffff)

OFP_Flow_Wildcards =   enum(OFPFW_IN_PORT       = 1 << 0,
                            OFPFW_DL_VLAN       = 1 << 1,
                            OFPFW_DL_SRC        = 1 << 2,
                            OFPFW_DL_DST        = 1 << 3,
                            OFPFW_DL_TYPE       = 1 << 4,
                            OFPFW_NW_PROTO      = 1 << 5,
                            OFPFW_TP_SRC        = 1 << 6,
                            OFPFW_TP_DST        = 1 << 7,
                            OFPFW_ALL           = ((1 << 22) - 1))

class BinaryHeader(object):
    def __init__(self):
        self.values = []
        self.data = {}

    def add_value(self, n, t):
        self.values.append((n, t))
        r = re.search('^[0-9]', t)
        if r is not None:
            self.data[n] = ''
        else:
            self.data[n] = 0

    def set(self, n, v):
        self.data[n] = v

    def get(self, n):
        return self.data[n]

    def pack(self):
        out = ''
        for n, t in self.values:
            out += struct.pack('>'+t, self.data[n])
        
        return out

    def read(self, data, count=0):
        fmt = '>'
        i = 0
        for _, t in self.values:
            if count > 0 and i >= count:
                break
            fmt += t
            i += 1
        
        rec = struct.unpack(fmt, data)
        for i in range(len(rec)):
            self.data[self.values[i][0]] = rec[i]

    def dump(self):
        for n, _ in self.values:
            if isinstance(self.data[n], int):
                print n+': '+str(self.data[n])
            else:
                print n+': '+(' '.join(x.encode('hex') for x in self.data[n]))

class OFP_Header(BinaryHeader):
    def __init__(self, t=0, l=0):
        p = super(OFP_Header, self)
        p.__init__()
        p.add_value('version', 'B')
        p.add_value('type', 'B')
        p.add_value('length', 'H')
        p.add_value('xid', 'I')
        self.length = 8

        self.set('version', 1)
        self.set('type', t)
        self.set('length', l)
        self.set('xid', random.getrandbits(32))

class OFP_Match(BinaryHeader):
    def __init__(self):
        p = super(OFP_Match, self)
        p.__init__()
        p.add_value('wildcards', 'I')
        p.add_value('in_port', 'H')
        p.add_value('dl_src', str(OFP_ETH_ALEN)+'s')
        p.add_value('dl_dst', str(OFP_ETH_ALEN)+'s')
        p.add_value('dl_vlan', 'H')
        p.add_value('dl_vlan_pcp', 'B')
        p.add_value('pad1', 'B')
        p.add_value('dl_type', 'H')
        p.add_value('nw_tos', 'B')
        p.add_value('nw_proto', 'B')
        p.add_value('pad2', '2s')
        p.add_value('nw_src', 'I')
        p.add_value('nw_dst', 'I')
        p.add_value('tp_src', 'H')
        p.add_value('tp_dst', 'H')
        self.length = 40

class OFP_Action_Header(BinaryHeader):
    def __init__(self):
        p = super(OFP_Action_Header, self)
        p.__init__()
        p.add_value('type', 'H')
        p.add_value('len', 'H')
        p.add_value('pad', '4s')
        self.length = 8

class OFP_Action_Output(BinaryHeader):
    def __init__(self):
        p = super(OFP_Action_Output, self)
        p.__init__()
        p.add_value('type', 'H')
        p.add_value('len', 'H')
        p.add_value('port', 'H')
        p.add_value('max_len', 'H')
        self.length = 8

class OFP_Action_Mod_Dl_Dst(BinaryHeader):
    def __init__(self):
        p = super(OFP_Action_Mod_Dl_Dst, self)
        p.__init__()
        p.add_value('type', 'H')
        p.add_value('len', 'H')
        p.add_value('dl_dst', '6s')
        p.add_value('pad', '6s')
        self.length = 16

class OFP_Flow_Mod(BinaryHeader):
    def __init__(self):
        p = super(OFP_Flow_Mod, self)
        p.__init__()
        # struct ofp_header header
        # struct ofp_match match
        p.add_value('cookie', 'Q')
        p.add_value('command', 'H')
        p.add_value('idle_timeout', 'H')
        p.add_value('hard_timeout', 'H')
        p.add_value('priority', 'H')
        p.add_value('buffer_id', 'I')
        p.add_value('out_port', 'H')
        p.add_value('flags', 'H')
        self.length = 24
        # struct ofp_action_header actions[0]

class OFP_Packet_Out(BinaryHeader):
    def __init__(self):
        p = super(OFP_Packet_Out, self)
        p.__init__()
        # struct ofp_header header
        p.add_value('buffer_id', 'I')
        p.add_value('in_port', 'H')
        p.add_value('actions_len', 'H')
        self.length = 8
        # struct ofp_action_header actions[0]
        # uint8_t data[0]

class OFP_Stats_Request(BinaryHeader):
    def __init__(self):
        p = super(OFP_Stats_Request, self)
        p.__init__()
        # struct ofp_header header
        p.add_value('type', 'H')
        p.add_value('flags', 'H')
        self.length = 4
        # uint8_t body[0]

class OFP_Stats_Reply(BinaryHeader):
    def __init__(self):
        p = super(OFP_Stats_Reply, self)
        p.__init__()
        p.add_value('type', 'H')
        p.add_value('flags', 'H')
        self.length = 4
        # uint8_t body[0]

class OFP_Flow_Stats_Request(BinaryHeader):
    def __init__(self):
        p = super(OFP_Flow_Stats_Request, self)
        p.__init__()
        # struct ofp_match match
        p.add_value('table_id', 'B')
        p.add_value('pad', 'B')
        p.add_value('out_port', 'H')
        self.length = 4

class OFP_Flow_Stats(BinaryHeader):
    def __init__(self):
        p = super(OFP_Flow_Stats, self)
        p.__init__()
        p.add_value('length', 'H')
        p.add_value('table_id', 'B')
        p.add_value('pad', 'B')
        # struct ofp_match match
        p.add_value('duration_sec', 'I')
        p.add_value('duration_nsec', 'I')
        p.add_value('priority', 'H')
        p.add_value('idle_timeout', 'H')
        p.add_value('hard_timeout', 'H')
        p.add_value('pad2', '6s')
        p.add_value('cookie', 'Q')
        p.add_value('packet_count', 'Q')
        p.add_value('byte_count', 'Q')
        self.length = 48 # without ofp_match
        # struct ofp_action_header actions[0]

class OFP_Error(BinaryHeader):
    def __init__(self):
        p = super(OFP_Error, self)
        p.__init__()
        p.add_value('type', 'H')
        p.add_value('code', 'H')
        # uint8_t data[0]
        self.length = 4

class OFlowNet:
    """
    Class handling a connection to an OpenFlow switch
    """
    def __init__(self):
        self.sock = None
        self.flows = []

    def connect(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def disconnect(self):
        self.sock.close()

    def send(self, msg):
        totalsent = 0
        while totalsent < len(msg):
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent += sent

    def recv(self):
        chunk = self.sock.recv(65535)
        if len(chunk) == 0:
            raise RuntimeError("socket connection broken(2)")
        return chunk

    def dump_flows(self):
        ofp_match = OFP_Match()
        ofp_match.set('wildcards', OFP_Flow_Wildcards.OFPFW_ALL)

        ofp_fsreq = OFP_Flow_Stats_Request()
        ofp_fsreq.set('table_id', 0xff)
        ofp_fsreq.set('out_port', OFP_Port_No.OFPP_NONE)

        ofp_streq = OFP_Stats_Request()
        ofp_streq.set('type', OFP_Stats_Types.OFPST_FLOW)

        body = ofp_streq.pack() + ofp_match.pack() + ofp_fsreq.pack()

        ofp_hdr = OFP_Header(OFP_Type.OFPT_STATS_REQUEST, len(body)+8)

        self.send(ofp_hdr.pack()+body)

    def packet_out(self, inport, pkt, outport=OFP_Port_No.OFPP_TABLE):
        # ofp_header + ofp_packet_out + ofp_action_header + data

        ofp_action = OFP_Action_Output()
        ofp_action.set('type', OFP_Action_Type.OFPAT_OUTPUT)
        ofp_action.set('len', 8)
        ofp_action.set('port', outport)
        ofp_action.set('max_len', 256)

        ofp_packet_out = OFP_Packet_Out()
        ofp_packet_out.set('buffer_id', 0xffffffff)
        ofp_packet_out.set('in_port', inport)
        ofp_packet_out.set('actions_len', ofp_action.get('len'))

        body = ofp_packet_out.pack() + ofp_action.pack() + pkt

        ofp_hdr = OFP_Header(OFP_Type.OFPT_PACKET_OUT, len(body)+8)

        self.send(ofp_hdr.pack()+body)

    def mod_flow(self, ofp_match, ofp_flow_mod, actions):
        actpack = ''
        for act in actions:
            actpack += act.pack()

        body = ofp_match.pack() + ofp_flow_mod.pack() + actpack

        ofp_hdr = OFP_Header(OFP_Type.OFPT_FLOW_MOD, len(body)+8)
        self.send(ofp_hdr.pack()+body)

    def parse_hello(self, hdr, msg):
        hdr2 = OFP_Header()
        hdr2.set('version', hdr.get('version'))
        hdr2.set('type', OFP_Type.OFPT_HELLO)
        hdr2.set('length', hdr2.length)
        hdr2.set('xid', hdr.get('xid'))
        self.send(hdr2.pack())

    def parse_ping(self, hdr, msg):
        print 'Ping'
        hdr2 = OFP_Header()
        hdr2.set('version', hdr.get('version'))
        hdr2.set('type', OFP_Type.OFPT_ECHO_REPLY)
        hdr2.set('length', hdr.get('length'))
        hdr2.set('xid', hdr.get('xid'))
        self.send(hdr2.pack()+msg[:(hdr.get('length')-hdr2.length)])

    def parse_stats(self, hdr, msg):
        blen = hdr.get('length') - 8

        ofp_streply = OFP_Stats_Reply()
        offset = ofp_streply.length
        ofp_streply.read(msg[:offset])

        if ofp_streply.get('type') == OFP_Stats_Types.OFPST_FLOW:
            while offset < blen:
                offset += self.parse_stats_flow(ofp_streply, msg[offset:])
        else:
            print 'Unknown stats type %d' % (ofp_streply.get('type'))

    def parse_stats_flow(self, hdr, msg):
        ofp_fwst = OFP_Flow_Stats()
        ofp_match = OFP_Match()
        ofp_action = OFP_Action_Header()

        ofp_fwst.read(msg[:4]+msg[4+40:88])
        ofp_match.read(msg[4:4+40])

        plen = ofp_fwst.get('length')
        rlen = 88

        actions = []

        while rlen < plen:
            ofp_action.read(msg[rlen:rlen+ofp_action.length])
            if ofp_action.get('type') == OFP_Action_Type.OFPAT_OUTPUT:
                ofp_action_out = OFP_Action_Output()
                ofp_action_out.read(msg[rlen:rlen+ofp_action_out.length])
                actions.append(ofp_action_out)
            rlen += ofp_action.get('len')

        self.flows.append({"body": ofp_fwst, "match": ofp_match, "actions": actions})

        return plen

    def parse_error(self, hdr, msg):
        ofp_error = OFP_Error()
        ofp_error.read(msg[:ofp_error.length])
        print 'Got error type %d code %d' % (ofp_error.get('type'), ofp_error.get('code'))

    def handshake(self):
        msg = self.recv()
        hdr = OFP_Header()
        hdr.read(msg[:hdr.length])

        if hdr.get('type') == OFP_Type.OFPT_HELLO:
            self.parse_hello(hdr, msg[hdr.length:])
        else:
            print 'Failed handshake'

    def run(self, outcond=None):
        while True:
            msg = self.recv()
            hdr = OFP_Header()
            hdr.read(msg[:hdr.length])

            if hdr.get('type') == OFP_Type.OFPT_HELLO:
                self.parse_hello(hdr, msg[hdr.length:])
            elif hdr.get('type') == OFP_Type.OFPT_ECHO_REQUEST:
                self.parse_ping(hdr, msg[hdr.length:])
            elif hdr.get('type') == OFP_Type.OFPT_STATS_REPLY:
                self.parse_stats(hdr, msg[hdr.length:])
            elif hdr.get('type') == OFP_Type.OFPT_ERROR:
                self.parse_error(hdr, msg[hdr.length:])
            else:
                print 'Unknown command type %d' % (hdr.get('type'))
            print '\n'

            if outcond is not None and hdr.get('type') == outcond:
                return

if __name__ == "__main__":
    ofnet = OFlowNet()
    ofnet.connect('127.0.0.1', 6634)
    ofnet.run()
