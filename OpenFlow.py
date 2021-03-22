from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import (ethernet, ipv4, ipv6)
from ryu.topology import event, switches
from ryu.lib import hub
import networkx as nx
import time
from struct import *
from collections import namedtuple


################################################################################
# 03-2021 OpenFlow Monitoring for Course HPDN
# Developed By H.Ji karen-in-winter@hotmail.com 
# collect several matrices in the separate structure
# throughput, delay, loss
################################################################################

class Flow():
	def __init__ (self, src, dst, sid, did, port):
		#values needed to identify the flow (src mac, dst mac, first and last switch)
		self.destinationSwitch = did
		self.sourceSwitch = sid
		self.src_mac = src
		self.dst_mac = dst
		#port from the first switch specifing the port to which the probe packet will be sent out to 
		self.sourcePort = port 
		self.delay = 0  #delay of the probe packet
		self.throughput = 0
		self.bytes_last = 0
		###############################################################################################
		self.rtt_s_c_src = 0 #the round trip time between the source switch and the controller
		self.rtt_s_c_dst = 0 #the round trip time between the destination switch and the controller
		
		self.packet_src_last = 0
		self.packet_dst_last = 0
		###############################################################################################
		self.packet_src = 0 #the total packet sent by the source switch
		self.packet_dst = 0 #the total packet received by the dst switch
		
		self.packet_loss = 0 #packet loss 
		
		self.src_timestamp = 0 #record the current timestamp of the request message of source switch
		self.dst_timestamp = 0 #record the current timestamp of the request message of dst switch

		self.monitor_period = 0 #record the time interval for monitoring 


	def __eq__(self, other):
	#override the default equal behaviour 
		if isinstance(other, self.__class__):
			return (self.src_mac == other.src_mac) and (self.dst_mac == other.dst_mac)
		else:
			return False

	def __ne__(self, other):
	#override the default unequal behaviour 
		if isinstance(other, self.__class__):
			return (self.src_mac != other.src_mac) or (self.dst_mac != other.dst_mac) 
		else:
			return False
	
	# return message of QOS paramters
	# throughput, delay, loss 
	def __str__ (self):
		# compute loss rate
		self.packet_loss = (self.packet_src - self.packet_dst)		
		if self.packet_src > 0:
			loss_rate = self.packet_loss*100/self.packet_src
		else:
			loss_rate = 0
		# compute delay
		delay_dur = self.delay - 0.5*( self.rtt_s_c_src + self.rtt_s_c_dst )
 	
		return 's%d-->s%d (%s - %s) - (%s kbps %s ms) (%s ms %s ms %s ms) (%s %s %s pkt/s %d %%)' \
			% (self.destinationSwitch, self.sourceSwitch, self.dst_mac, self.src_mac, self.throughput, delay_dur*1000, \
			   self.delay*1000, self.rtt_s_c_src*1000, self.rtt_s_c_dst*1000, self.packet_src, self.packet_dst, self.packet_loss, int(loss_rate))


class Monitoring(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(Monitoring, self).__init__(*args, **kwargs)
		self.network = nx.DiGraph()
                # the time interval to poll the monitoring
 		self.monitor_period = 2
		self.PROBE_ETHERTYPE = 0x07C7 #different ethtype used for probe packets
		self.monitor_thread = hub.spawn(self._monitor)
		self.monitored_paths = [] #array to store information about flows we wish to monitor 
   
	#Switch connected
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		dp = ev.msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
			
		#Add table-miss flow entry
		#Forward all unmatched packets to the controller
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
		instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		cmd = parser.OFPFlowMod(datapath=dp, priority=0,
		match=match, instructions=instr)
		dp.send_msg(cmd)

	#This function gets triggered before
	#the topology flow detection entries are added
	#But late enough to be able to remove flows
	@set_ev_cls(ofp_event.EventOFPStateChange, CONFIG_DISPATCHER)
	def state_change_handler(self, ev):
		dp = ev.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser
        
		#Delete any possible currently existing flow entry.
		del_flows = parser.OFPFlowMod(dp, table_id=ofp.OFPTT_ALL,
		out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
		command=ofp.OFPFC_DELETE)
		dp.send_msg(del_flows)
		
		#Delete any possible currently exising groups
		del_groups = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_DELETE,
		group_id=ofp.OFPG_ALL)
		dp.send_msg(del_groups)
		
		#Ensure deletion is finished before additional flows are added
		barrier_req = parser.OFPBarrierRequest(dp)
		dp.send_msg(barrier_req)

	#Monitoring thread 
	#this function is exceuted periodiclly 
	#poll all the monitored switches for information and generate all the requiered probe packets
	def _monitor(self):
		"""
		Main method for the monitoring actions.
		"""
		while True:
			self.logger.info('Monitoring stats: num_flows:' + str(len(self.monitored_paths)))
			for m in self.monitored_paths: 
				print m
				# send request statistics command to the source switch of the monitored flow
				self.request_stats(m.sourceSwitch, m.src_mac, m.dst_mac, time.time())
				# send request statistics command to the destination switch of the monitored flow
				self.request_stats(m.destinationSwitch, m.src_mac, m.dst_mac, time.time())
				self.send_latency_probe_packet(m.sourceSwitch, m.sourcePort, m.src_mac, m.dst_mac)
			hub.sleep(self.monitor_period)
	

		
	#send flow stats request to switch 
	def request_stats(self, sid, src, dst, timestamp):
		""" Send statistics request to a switch sid
		Arguments:
		sid: switch id
		src: src mac address
	    dst: dst mac address
        """
		
		matches = [flow for flow in self.monitored_paths if (flow.src_mac == src and flow.dst_mac == dst)]
		
		# if the request is from the last switch in the path, record the current time
		if sid == matches[0].destinationSwitch:
			matches[0].dst_timestamp = timestamp
					

		# if the request is from the first switch, record the current time				
		if sid == matches[0].sourceSwitch:
			matches[0].src_timestamp = timestamp
		
		dp = self.network.node[sid]['switch'].dp
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		#only ask for the stats for the flow we monitor 
		#If this wasnt included we would request all the flows. This would 
		#increasse the processing delay at the switch
		match = parser.OFPMatch(eth_src = src, eth_dst = dst)
		req = parser.OFPFlowStatsRequest(dp, match=match)
		dp.send_msg(req)

				
		
	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply(self, ev):
		"""Process flow stats reply info.
		Calculate flow speed and save it.
		"""

		sid = ev.msg.datapath.id
		body = ev.msg.body

		
		#self.logger.info('Receiving statistics from switch ' + str(sid))
		#process the reply message 

		for stat in body:
			#the switch will return the stats for all flow entries that match src and dst address
			# eth_type 2048 or 0x0800 ipv4 protocol
			if "eth_type" not in stat.match or stat.match["eth_type"]==2048:
	 			#find a flow from monitored_paths that corresponds to this reply
				matches = [flow for flow in self.monitored_paths if (flow.src_mac == stat.match["eth_src"] and flow.dst_mac == stat.match["eth_dst"])]
				#there should be only one match as we sent the requests with the match field
				
				# if the request is from the last switch in the path, calculate the bandwidth
				if sid == matches[0].destinationSwitch:
					matches[0].throughput = 8*(stat.byte_count-matches[0].bytes_last)/(1000*self.monitor_period)
					matches[0].bytes_last = stat.byte_count
					#######################################################################
					##calculate the round trip time between the switch and the controller##
					#######################################################################
					matches[0].rtt_s_c_dst = time.time() - matches[0].dst_timestamp
					matches[0].packet_dst = stat.packet_count - matches[0].packet_dst_last
					matches[0].packet_dst_last += stat.packet_count - matches[0].packet_dst_last
					matches[0].monitor_period = self.monitor_period
					
					
				# if the request is from the first switch, only record the round trip time between the controller and the switch				
				if sid == matches[0].sourceSwitch:
					matches[0].rtt_s_c_src = time.time() - matches[0].src_timestamp
					matches[0].packet_src = stat.packet_count - matches[0].packet_src_last
					matches[0].packet_src_last += stat.packet_count - matches[0].packet_src_last
					matches[0].monitor_period = self.monitor_period
				


	def send_latency_probe_packet(self, sid, port, src, dst):
		'''
		Injects latency probe packets in the network
		Arguments:
		sid: switch id
		src: src mac address
		dst: dst mac address
		port: output port
		'''
		#self.logger.info('Injecting latency probe packets')
		dp = self.network.node[sid]['switch'].dp
		actions = [dp.ofproto_parser.OFPActionOutput(port)]

		pkt = packet.Packet()
		#probe packet should have the same source and destination mac as the packets belonging to the monitored flow
		#these packets should be matched by the rules of the original flow on all the switches except the 
		#first one
		pkt.add_protocol(ethernet.ethernet(ethertype=self.PROBE_ETHERTYPE, dst=dst, src=src))        
		pkt.serialize()
		payload = '%d;%f' % (sid, time.time())
		data = pkt.data + payload
			
		out = dp.ofproto_parser.OFPPacketOut(
						datapath=dp,
						buffer_id=dp.ofproto.OFP_NO_BUFFER,
						data=data,
						in_port=dp.ofproto.OFPP_CONTROLLER,
						actions=actions)
		##self.logger.info("Probe sent!")
		dp.send_msg(out)

	#Topology Events
	@set_ev_cls(event.EventSwitchEnter)
	def switchEnter(self,ev):
		switch = ev.switch
		sid = switch.dp.id

		self.network.add_node(sid, switch = switch, flows= {}, host = False)
		
		self.logger.info('Added switch ' + str(sid))

	@set_ev_cls(event.EventSwitchLeave)
	def switchLeave(self,ev):
		switch = ev.switch
		sid = switch.dp.id
		self.logger.info('Received switch leave event: ' + str(sid))

	@set_ev_cls(event.EventLinkAdd)
	def linkAdd(self,ev):
		link = ev.link
		src = link.src.dpid
		dst = link.dst.dpid
		
		src_port = link.src.port_no
		dst_port = link.dst.port_no
		
		self.network.add_edge(src, dst, src_port = src_port, dst_port = dst_port)     		
		self.logger.info('Added link from ' + str(src) + ' to ' + str(dst))

	@set_ev_cls(event.EventLinkDelete)
	def linkDelete(self,ev):
		link = ev.link
		src = link.src.dpid
		dst = link.dst.dpid
		
		self.logger.info('Received link delete event: ' + str(src) + ' to ' + str(dst))

	@set_ev_cls(event.EventHostAdd)
	def hostFound(self,ev):
		host = ev.host
		sid = host.port.dpid
		port = host.port.port_no
		mac = host.mac
		
		self.network.add_node(mac, host = True)
		self.network.add_edge(mac, sid, src_port = -1, dst_port = port)
		self.network.add_edge(sid, mac, src_port = port, dst_port = -1)
		
		self.logger.info('Added host ' + mac + ' at switch ' + str(sid))

	def _add_flow_entry(self, sid, src, dst, port):
		"""Adds flow entries on switch sid,
		outputting all (allowed) traffic with destination address dst to port.
		
		Arguments:
		sid: switch id
		src: src mac address
		dst: dst mac address
		port: output port
		ethtype: ethernet type
		"""
		dp = self.network.node[sid]['switch'].dp
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		#add flow rule to match all other data packets 
		match = parser.OFPMatch(eth_src = src, eth_dst = dst)
		actions = [parser.OFPActionOutput(port)]
		priority = 1

		instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		cmd = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=instr)
		dp.send_msg(cmd)
		
		self.logger.info('ADDED FLOWS ON SWITCH ' + str(sid) + " TO DESTINATION " + str(dst))

	def _add_probe_flow_entry(self, sid, src, dst, port):
		"""Adds  probe flow entry on switch sid,
		outputting all (allowed) traffic with destination address dst to port.
		
		Arguments:
		sid: switch id
		src: src mac address
		dst: dst mac address
		port: output port
		ethtype: ethernet type
		"""
		dp = self.network.node[sid]['switch'].dp
		ofp = dp.ofproto
		parser = dp.ofproto_parser
		match = parser.OFPMatch(eth_src = src, eth_dst = dst, eth_type = self.PROBE_ETHERTYPE)
		actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
		priority = 2       

		instr = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		cmd = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=instr)
		dp.send_msg(cmd)
		
		self.logger.info('ADDED PROBE ENTRY ON SWITCH ' + str(sid) + " TO DESTINATION " + str(dst))

	#Packet received
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth = pkt[0]
		src = eth.src
		dst = eth.dst
		if eth.protocol_name != 'ethernet':
			#We should not receive non-ethernet packets
			self.logger.warning('Received unexpected packet:')
			self.logger.warning(str(pkt))
			return
        
		#Don't do anything with LLDP, not even logging
		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		#Save the timestamp from the probe packet and calculate path delay
		if eth.ethertype == self.PROBE_ETHERTYPE:
			#self.logger.info('Received probe packet')
			data = pkt[1] #data (ip header + timestamp(when the probe packet was sent)) is the payload  
			split_data = data.split(';') 
			timestamp = split_data[len(split_data)-1] #last field is the timestamp
			matches = [flow for flow in self.monitored_paths if (flow.src_mac == src and flow.dst_mac == dst)]
			######################################################################
			# the injected probe packet, the delay time of the controller (Drtt) #
			######################################################################
			matches[0].delay = time.time() - float(timestamp)
			# matches[0].delay = time.time() - float(timestamp) - 0.5*( matches[0].rtt_s_c_src + matches[0].rtt_s_c_dst)
			# matches[0].packet_loss = (matches[0].packet_src - matches[0].packet_dst)
			return

		self.logger.info('Received ethernet packet')
		self.logger.info('From ' + src + ' to ' + dst)

		if dst not in self.network:
		#We have not yet received any packets from dst
		#So we do not now its location in the network
		#Simply broadcast the packet to all ports without known links
			self._broadcast_unk(msg.data)
			return
        
		dp = msg.datapath
		sid = dp.id
		if eth.ethertype == 0x0800:
		#Compute path to dst
			try:        
				path = nx.shortest_path(self.network, source=sid, target=dst)
			except (nx.NetworkXNoPath, nx.NetworkXError):
				self.logger.warning('No path from switch ' + str(sid) + ' to ' + dst)
				return False
            
			self._install_path(src, path)

			#Send packet directly to dst
			self._output_packet(path[-2], [self.network[path[-2]][path[-1]]['src_port']], msg.data)
	 
			#add flow to monitoring
			self.logger.info('ADDED FLOW TO MONITORING')
			flow = Flow(src, dst, sid, path[len(path)-2], self.network[path[0]][path[1]]['src_port'])
			if flow not in self.monitored_paths:
				self.monitored_paths.append(flow)
       
	def _install_path(self, src, path):
		"""Installs path in the network. 
		path[-1] should be a host,
		all other elements of path are required to be switches
		
		Arguments:
		path: Sequence of network nodes
		"""
        
		# the destination host
		dst = path[-1]

		for i in range(0,len(path)-1):
			current = path[i]
			next = path[i+1]
            
			port = self.network[current][next]['src_port']
			self._add_flow_entry(current, src, dst, port)
			#add additonal rule for a probe packet at the last switch
			if i == len(path)-2:
				self._add_probe_flow_entry(current, src, dst, port)
            
	def _output_packet(self, sid, ports, data):
		"""Output packet to ports ports of switch sid
			
		Arguments:
		sid: switch id
		ports: output ports
		data: packet
		"""

		self.logger.info('Outputing packet to ports ' + str(ports) + ' of switch ' + str(sid))
        	
		dp = self.network.node[sid]['switch'].dp
		ofp = dp.ofproto
		parser = dp.ofproto_parser
        	
		actions = [parser.OFPActionOutput(port) for port in ports]        
		cmd = parser.OFPPacketOut(dp, buffer_id = ofp.OFP_NO_BUFFER,
		in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
		dp.send_msg(cmd)

	def _broadcast_unk(self, data):
		"""Output packet to all ports in the network without known links        
		Arguments:
		data: packet
		"""
	    
		for node in self.network:
			if not self.network.node[node]['host']:
				switch = self.network.node[node]['switch']
                
				all_ports = [p.port_no for p in switch.ports]
                
				#If the number of links per switch is very large
				#it might be more efficient to generate a set instead of a list
				#of known ports
				known_ports = [self.network[node][neighbor]['src_port']
				for neighbor in self.network.neighbors(node)]
		        	unk_ports = [port for port in all_ports if port not in known_ports]                
				self._output_packet(node, unk_ports, data)
