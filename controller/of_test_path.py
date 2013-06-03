from pox.core import core
import pox.openflow.libopenflow_01 as of
import re, random
import tools

log = core.getLogger()

constraints = {}

constraints[1] = {4:2, 5:3, 6:3}
constraints[2] = {6:4}
constraints[3] = {6:5}
constraints[4] = {1:3}
constraints[5] = {1:2}
constraints[6] = {1:4, 2:4, 3:4}

mapping = tools.Mapping("/home/openflow/code/conf/mapping.txt")
ttopo = tools.Topology("/home/openflow/tests/test02_topo.txt")

class TestPathCtrl (object):
  def __init__ (self, connection):
    self.connection = connection
    # This binds our PacketIn event listener
    connection.addListeners(self)

  def send_packet (self, buffer_id, raw_data, out_port, in_port):
    """
    Sends a packet out of the specified switch port.
    If buffer_id is a valid buffer on the switch, use that.  Otherwise,
    send the raw data in raw_data.
    The "in_port" is the port number that packet arrived on.  Use
    OFPP_NONE if you're generating this packet.
    """
    msg = of.ofp_packet_out()
    msg.in_port = in_port
    if buffer_id != -1 and buffer_id is not None:
      # We got a buffer ID from the switch; use that
      msg.buffer_id = buffer_id
    else:
      # No buffer ID from switch -- we got the raw data
      if raw_data is None:
        # No raw_data specified -- nothing to send!
        return
      msg.data = raw_data

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def process_packet(self, packet, packet_in):
    sid = self.connection.dpid
    dstmac = str(packet.dst)
    dnode = mapping.get_node_from_mac(dstmac)

    if dnode is None: # FLOOOOD
        self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)
        return

    oport = None

    print 'Switch %d received packet to %d' % (sid, dnode)

    # Destination directly connected to me
#    print 'Checking connection between nodes sid,dnode %d %d' % (sid, dnode)
    if ttopo.is_connected(sid, dnode):
      oport = ttopo.get_port(sid, dnode)
      print '%d and %d directly connected, sending to port %d' % (sid, dnode, oport)
    else:
      edges = ttopo.get_edges(dnode)
      dsid = edges[0] # Assume no multihoming
      # Destination is a neighbor
      print 'Dnode %d is connected to switch %d' % (dnode, dsid)
      if ttopo.is_connected(sid, dsid):
        oport = ttopo.get_port(sid, dsid)
        print 'Dsid %d and me %d connected, sending to port %d' % (dsid, sid, oport)
      else:
        # Destination is remote and we have a constraint for it
        if sid in constraints and dsid in constraints[sid]:
          gw = constraints[sid][dsid]
          oport = ttopo.get_port(sid, gw)

    if oport is not None:
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_dst = packet.dst
      msg.actions.append(of.ofp_action_output(port = oport))
      self.connection.send(msg)
      self.send_packet(packet_in.buffer_id, packet_in.data, oport, packet_in.in_port)
#    else: #FLOOOOOD
#      self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
#    self.act_like_lb(packet, packet_in)
    self.process_packet(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    TestPathCtrl(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
