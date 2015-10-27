####

# Copyright 2015 Hongxu Chen, Hao Chen
#
# 
# This file is loosely based on the discovery component in NOX.

import time
from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str, str_to_bool
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import os

import struct
import time
from collections import namedtuple
from random import shuffle, random


log = core.getLogger()
PortByDpid = namedtuple("portToDpidInfo",('dpid','port_num','port_addr'))

'''
A list that stores all port-switch information
'''
_portInfo = []

isPacketOutSent = False

linkCount = 0



class LinkEvent (Event):
  """
  Link up/down event
  """
  def __init__ (self, add, link):
    Event.__init__(self)
    self.link = link
    self.added = add
    self.removed = not add

  def port_for_dpid (self, dpid):
    if self.link.dpid1 == dpid:
      return self.link.port1
    if self.link.dpid2 == dpid:
      return self.link.port2
    return None


class Link (namedtuple("LinkBase",("dpid1","port1","dpid2","port2"))):
  @property
  def uni (self):
    """
    Returns a "unidirectional" version of this link

    The unidirectional versions of symmetric keys will be equal
    """
    pairs = list(self.end)
    pairs.sort()
    return Link(pairs[0][0],pairs[0][1],pairs[1][0],pairs[1][1])

  @property
  def end (self):
    return ((self[0],self[1]),(self[2],self[3]))

  def __str__ (self):
    return "Switch %s:%s --> Switch %s:%s" %(str(self[0]),self[1],str(self[2]),self[3])
    #return "%s.%s -> %s.%s" %(dpid_to_str(self[0]),self[1],
                               #dpid_to_str(self[2]),self[3])
    

  def __repr__ (self):
    return "Link(dpid1=%s,port1=%s, dpid2=%s,port2=%s)" % (self.dpid1,
        self.port1, self.dpid2, self.port2)


class Discovery (EventMixin):
  """
  Component that attempts to discover network toplogy.

  Sends out specially-crafted LLDP packets, and monitors their arrival.
  """

  _flow_priority = 65000     # Priority of LLDP-catching flow (if any)
  _link_timeout = 10         # How long until we consider a link dead
  _timeout_check_period = 5  # How often to check for timeouts

  _eventMixin_events = set([
    LinkEvent,
  ])

  _core_name = "openflow_discoveryV3" 

  Link = Link
#*************************************************************Initializing**************************************
  def __init__ (self, install_flow = True, explicit_drop = True,
                link_timeout = None, eat_early_packets = False):
    self._eat_early_packets = eat_early_packets
    self._explicit_drop = explicit_drop
    self._install_flow = install_flow
    self.adjacency = {} # From Link to time.time() stamp
    # Listen with a high priority (mostly so we get PacketIns early)
    core.listen_to_dependencies(self,
        listen_args={'openflow':{'priority':0xffffffff}})
    #Timer(self._timeout_check_period, self._expire_links, recurring=True)
    
  @property
  def send_cycle_time (self):
    return self._link_timeout / 2.0

#*************************************************************Install flow**************************************
  def install_flow (self, con_or_dpid, priority = None):
    if priority is None:
      priority = self._flow_priority
    if isinstance(con_or_dpid, (int,long)):
      con = core.openflow.connections.get(con_or_dpid)
      if con is None:
        log.warn("Can't install flow for %s", dpid_to_str(con_or_dpid))
        return False
    else:
      con = con_or_dpid 

    #portPerSwitch stores all ports in one switch
    portItem = namedtuple("portItem",('port_num','port_addr'))
    portPerSwitch = []
    # Store all ports of a switch
    for p in _portInfo:
      if p.dpid == con.dpid:
        portPerSwitch.append(portItem(p.port_num,p.port_addr))
    #print'S',con.dpid,'ports',portPerSwitch

    for pByID in _portInfo:
      if pByID.port_num != 65534 and pByID.dpid == con.dpid:
        match = of.ofp_match(dl_type = pkt.ethernet.LLDP_TYPE,
                          dl_dst = pkt.ETHERNET.NDP_MULTICAST,in_port = pByID.port_num)
        #print'Ingress Port:',pByID.port_num
        msg = of.ofp_flow_mod()
        msg.priority = priority
        msg.match = match
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        for p in portPerSwitch:
          if p.port_num != 65534 and p.port_num != pByID.port_num:
            #print'Install flow====Rewrites',p.port_addr,', send Out from',p.port_num
            msg.actions.append(of.ofp_action_dl_addr.set_src(p.port_addr))
            msg.actions.append(of.ofp_action_output(port = p.port_num))
        con.send(msg)
        #print'Installing flows to switch', con.dpid
    return True
##*************************************************************handle_openflow_ConnectionUp********************************
  def _handle_openflow_ConnectionUp (self, event):
    print 'Switch connectted:  S',event.dpid
    #----------------made changes----------------------------------
    '''
    Once connection up, fetch port information on the switch, store it to global knowledge
    '''
    ports = [(p.port_no, p.hw_addr) for p in event.ofp.ports]
    for port_num, port_addr in ports:
      _portInfo.append(PortByDpid(event.dpid, port_num, port_addr))
      #print'*UPDATING: System Knowleage(_portInfo)*::: s',event.dpid,'port:', port_num,'MAC:', port_addr
    '''
    print'----------------------------------System Knowledge-------------------------------------'
    #:go through the port knowledge
    for port in _portInfo:
      for i in range(0,len(_portInfo)):
        if port.dpid == i+1:
          print'S',i+1,':',port.port_num,port.port_addr
    print'----------------------------------System Knowledge-------------------------------------'
    '''
    #-----------install preInstalled flow---------------------------------------
    global isPacketOutSent
    if isPacketOutSent is True:
      self.install_flow(event.connection)
    
    global timeStart
    timeStart = time.time()

    #-----------send out packetOut packet-----------------------------
    #print 'Is PacketOut Sent?:', isPacketOutSent
    if isPacketOutSent is not True:
      isPacketOutSent = True
      Timer(5, self._timer_handler, recurring=True)
      #packetOutItem = self.create_discovery_packet(event.dpid)
      #core.openflow.sendToDPID(event.dpid, packetOutItem)
 ##*********************************************************Timer*************************************** 
  
  def _timer_handler (self):
    dpid = _portInfo[0].dpid
    packetOutItem = self.create_discovery_packet(dpid)
    core.openflow.sendToDPID(dpid, packetOutItem) 
    return 

    
      


#****************************************************Create Discovery Packet**************************************************
  #----------Code from lldpsender--------------------------
  def create_discovery_packet (self, dpid):
    """
    Build discovery packet
    """
    chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
    chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])

    # Maybe this should be a MAC.  But a MAC of what?  Local port, maybe?
    port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(255))
    ttl = pkt.ttl(ttl = 120)
    sysdesc = pkt.system_description()
    sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

    discovery_packet = pkt.lldp()
    discovery_packet.tlvs.append(chassis_id)
    discovery_packet.tlvs.append(port_id)
    discovery_packet.tlvs.append(ttl)
    discovery_packet.tlvs.append(sysdesc)
    discovery_packet.tlvs.append(pkt.end_tlv())
    
    eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
    eth.src = "0x000000"
    eth.dst = pkt.ETHERNET.NDP_MULTICAST
    eth.payload = discovery_packet
    #---------------Made changes-----------------------
    actionSet = []
    selectedDpid = dpid
    #print'Sending PacketOut to SWitch', selectedDpid
    
    #:need to for all ports in one swtich
    for p in _portInfo:
      #packetOut floods exclueding the ingress (secure port to Controller)
      if p.port_num!=65534 and p.dpid == selectedDpid:
        actionSet.append(of.ofp_action_dl_addr.set_src(p.port_addr))
        actionSet.append(of.ofp_action_output(port=p.port_num))
    #print'actionSet-------->',actionSet
    po = of.ofp_packet_out(action = actionSet)
    po.data = eth.pack()
    return po.pack()


#**************************************************handle_openflow_PacketIn*******************************************
  def _handle_openflow_PacketIn (self, event):
    """
    Receive and process LLDP packets
    """
    #print'switch',event.dpid,'port',event.port
    packet = event.parsed
    #print'*PacketIn Message arriving*: {lldp src address}: ',packet.src
  
    if (packet.effective_ethertype != pkt.ethernet.LLDP_TYPE
        or packet.dst != pkt.ETHERNET.NDP_MULTICAST):
      #if not self._eat_early_packets: return
      #if not event.connection.connect_time: return
      #enable_time = time.time() - self.send_cycle_time - 1
      #if event.connection.connect_time > enable_time:
        #return EventHalt
      return
    
    for p in _portInfo:
      if p.port_addr == packet.src:
        #print'*Time using:',time.time()-timeStart
        #Create a detected link
        link = Discovery.Link(p.dpid, p.port_num, event.dpid, event.port)

        if link not in self.adjacency:
          self.adjacency[link] = time.time()
          global linkCount
          linkCount = linkCount+1
          log.info('No.%s,link detected: %s',linkCount,link)
          #if linkCount == 99:
            #os._exit(0)

          self.raiseEventNoErrors(LinkEvent, True, link)
        else:
          # Just update timestamp
          self.adjacency[link] = time.time()
    

def launch (no_flow = False, explicit_drop = True, link_timeout = None,
            eat_early_packets = False):
  explicit_drop = str_to_bool(explicit_drop)
  eat_early_packets = str_to_bool(eat_early_packets)
  install_flow = not str_to_bool(no_flow)
  if link_timeout: link_timeout = int(link_timeout)
  core.registerNew(Discovery, explicit_drop=explicit_drop,
                   install_flow=install_flow, link_timeout=link_timeout,
                   eat_early_packets=eat_early_packets)