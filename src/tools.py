#!/usr/bin/env python

"""
@author: David Lebrun <dav.lebrun@gmail.com>
"""

class Topology:
    """ Represent a network topology """

    def __init__(self, fname=None):
        self.nodes = {}
        self.edges = {}
        self.ports = {}

        if fname is not None:
            self.parse(fname)

    def set_port(self, snode, dnode, port):
        if snode not in self.ports:
            self.ports[snode] = {}
        self.ports[snode][dnode] = port

    def get_port(self, snode, dnode):
        return self.ports[snode][dnode]

    def add_node(self, nodeid, switch):
        if nodeid not in self.nodes:
            self.nodes[nodeid] = switch

    def add_edge(self, node1, node2):
        if node1 == node2:
            return

        # Avoid duplication
        if node1 < node2:
            nodeA, nodeB = node1, node2
        else:
            nodeA, nodeB = node2, node1

        if nodeA not in self.edges:
            self.edges[nodeA] = []

        if nodeB not in self.edges[nodeA]:
            self.edges[nodeA].append(nodeB)

    def is_switch(self, nodeid):
        return self.nodes[nodeid]

    def is_connected(self, node1, node2):
        if node1 < node2:
            nodeA, nodeB = node1, node2
        else:
            nodeA, nodeB = node2, node1

        return nodeB in self.edges[nodeA]

    # Get switches connected to a host
    def get_edges(self, node):
        edges = []
        for n in self.nodes:
            if not self.is_switch(n):
                continue
            if self.is_connected(node, n):
                edges.append(n)
        return edges

    # Get hosts connected to a switch
    def get_h_edges(self, node):
        edges = []
        for n in self.nodes:
            if self.is_switch(n):
                continue
            if self.is_connected(node, n):
                edges.append(n)
        return edges

    def parse(self, fname):
        """
            File format:

            s1 <-> hA-ethX hB-ethX hC-ethX ...
            s2 <-> ...
            ...
            sN <-> ...
        """

        f = open(fname, 'r')
        data = f.readlines()
        f.close()
        
        for line in data:
            line = line.strip()
            ldata = line.split(" ")

            sid = int(ldata[0][1:])

            self.add_node(sid, switch=True)

            for i in range(2, len(ldata)):
                hid = int(ldata[i].split("-")[0][1:])
                sw = ldata[i].split("-")[0][0] == 's'
                self.add_node(hid, switch=sw)
                self.add_edge(sid, hid)
                self.set_port(sid, hid, i-1)

class Mapping:
    def __init__(self, fname=None):
        self.mapping = {}

        if fname is not None:
            self.parse(fname)

    def parse(self, fname):
        """
            File format:

            nn IP mac port
            nn IP mac port
            ...
            nn is nodeID
            IP is IP address
            mac is mac address if host, x if switch
            port is openflow port if switch, 0 if host
        """
        f = open(fname, 'r')
        data = f.readlines()
        f.close()

        for line in data:
            line = line.strip()
            ldata = line.split(" ")
            
            self.mapping[int(ldata[0])] = (ldata[1], ldata[2], int(ldata[3]))

    def get_data(self, node):
        return self.mapping[node]

    def get_ip(self, node):
        return self.mapping[node][0]

    def get_mac(self, node):
        return self.mapping[node][1]

    def get_port(self, node):
        return self.mapping[node][2]

    def get_node_from_ip(self, target):
        for node in self.mapping:
            ip, _, _ = self.mapping[node]
            if ip == target:
                return node
        return None

    def get_node_from_mac(self, target):
        for node in self.mapping:
            _, mac, _ = self.mapping[node]
            if mac == target:
                return node
        return None

class TraceData:
    def __init__(self, src, dst, gcid, pktid=0):
        self.pktid = pktid
        self.src = src
        self.dst = dst
        self.gcid = gcid
        self.path = []
        self.ts = []
        self.delay = 0

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.gcid == other.gcid and self.pktid == other.pktid

    def __hash__(self):
        return hash(str(self.src)+str(self.dst)+str(self.gcid))

    def __str__(self):
        return '%d: %s -> %s path %s delay %f' % (self.gcid, str(self.src), str(self.dst), str(self.path), self.delay)
