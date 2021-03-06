from threading import Thread
from scapy.all import *
from data import Data
from event_system import EventListener, Event, EventProducer
from packet import ContikiPacket
import logging


class PacketSendToSerialEvent(Event):
    def __init__(self, data: ContikiPacket):
        Event.__init__(self, data)
        logging.debug('BRIDGE:Packet send to serial event')

    def __str__(self):
        return "incoming-packet-to-slip-event"


class PacketForwardToSerialEvent(Event):
    def __init__(self, data: ContikiPacket):
        Event.__init__(self, data)
        logging.debug('BRIDGE:Packet forward to serial event')

    def __str__(self):
        return "packet-forward-to-serial-event"


class NeighbourSolicitationEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)
        logging.debug('BRIDGE:Sending response to ICMPv6 neighbour solicitation for address "{}"'
                      .format(data['target_ip']))

    def __str__(self):
        return "mote-neighbour-solicitation-event"


class NeighbourAdvertisementEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)
        logging.debug('BRIDGE:Received ICMPv6 NA for ip"{}"'.format(data['src_l2_addr']))

    def __str__(self):
        return "neighbour-advertisement-event"


class RootPacketForwardEvent(Event):
    def __init__(self, data: ContikiPacket):
        Event.__init__(self, data)
        logging.debug('BRIDGE:Asking for forward decision for packet "{}"'.format(data.get_contiki_format()))

    def __str__(self):
        return "root-packet-forward"


class Ipv6PacketParser(EventProducer):
    """
    Class responsible for parsing some kind of packet formats
    """
    def __init__(self, data: Data, node_table):
        EventProducer.__init__(self)
        self._data = data
        self._node_table = node_table
        self.add_event_support(PacketSendToSerialEvent)
        self.add_event_support(NeighbourSolicitationEvent)
        self.add_event_support(NeighbourAdvertisementEvent)
        self.add_event_support(RootPacketForwardEvent)
        self.add_event_support(PacketForwardToSerialEvent)

    """
    Packed sent from another mote via WIFI must contains two IP headers, first one is used by internal WIFI, but second
    one contains motes global IPv6 address
    """
    def _parse_udp(self, packet: Ether):
        contiki_packet = ContikiPacket()
        contiki_packet.set_scapy_format(packet)

        ip = packet[IPv6]

        if self._data.get_mode() == Data.MODE_ROOT and ip[0].dst == self._data.get_configuration()['border-router']['ipv6']:
            ask = False
            node_address = self._node_table.get_node_address(ip[1].dst, 'rpl')
            if not node_address:
                logging.warning('BRIDGE:Mote not exists "{}"'.format(ip[1].dst))
            next_nodes = node_address.get_node_addresses()
            for key in next_nodes:
                if next_nodes[key].get_tech_type() == "wifi":
                    ask = True
                    # ask for forward decision (I have route to mote using wifi too)
                    self.notify_listeners(RootPacketForwardEvent(contiki_packet))
            if not ask:
                # forwarding packet using RPL (I don't have route to mote using wifi)
                self.notify_listeners(PacketForwardToSerialEvent(contiki_packet))
        elif ip[0].dst == self._data.get_wifi_global_address():
            if ip[1].dst == self._data.get_mote_global_address():
                self.notify_listeners(PacketSendToSerialEvent(contiki_packet))

    def _parse_icmpv6_ns(self, packet: Ether):      # refactor - add this to neighbour manager
        target_ip = packet[ICMPv6ND_NS].tgt
        src_ip = packet[IPv6].src
        src_l2 = packet.src
        # i I am root and solicitation wants to get root address or solicitation wants my mote address
        if (self._data.get_mode() == Data.MODE_ROOT and self._data.get_configuration()['border-router']['ipv6'] == target_ip)\
                or (str(self._data.get_mote_global_address()) == target_ip or str(self._data.get_mote_link_local_address()) == target_ip):
            self.notify_listeners(NeighbourSolicitationEvent({
                "src_l2": src_l2,
                "src_ip": src_ip,
                "target_ip": target_ip
            }))

    def _parse_icmpv6_na(self, packet: Ether):
        target_ip = packet[ICMPv6ND_NA].tgt
        src_ip = packet[IPv6].src
        self.notify_listeners(NeighbourAdvertisementEvent({
            "src_ip": src_ip,
            "target_ip": target_ip,
            "src_l2_addr": packet.src
        }))

    def parse(self, packet: Ether):
        if not self._data.get_mote_global_address():
            logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not compare incoming packet')
            return
        if IPv6 in packet and UDP in packet:
            try:
                packet[IPv6][1].dst     # stupid solution for checking dst packet address
                self._parse_udp(packet)
            except Exception as e:
                logging.error('BRIDGE:{}'.format(str(e)))
        if ICMPv6ND_NS in packet:
            self._parse_icmpv6_ns(packet)
        if ICMPv6ND_NA in packet:
            self._parse_icmpv6_na(packet)


class PacketSender(EventListener):
    """
    Class is reponsible for sending packet over WiFi interface, sending ICMPv6 NS,NA
    """
    def __init__(self, iface, data: Data, node_table):
        self.iface = iface
        self._data = data
        self._node_table = node_table

    def send_packet(self, contiki_packet: ContikiPacket):
        packet = contiki_packet.get_scapy_format()
        dst_ip = None
        dst_l2 = None
        if self._data.get_mode() == Data.MODE_NODE:
            dst_ip = self._data.get_configuration()['border-router']['ipv6']
            if self._data.get_border_router_l2_address():
                dst_l2 = self._data.get_border_router_l2_address()
            else:
                dst_l2 = "33:33:00:00:00:fb"        # todo check if it is correct
        else:
            node = self._node_table.get_node_address(packet[IPv6][1].dst, 'rpl')
            if node:
                next_nodes = node.get_node_addresses()
                for addr in next_nodes:
                    if next_nodes[addr].get_tech_type() == "wifi":
                        dst_ip = addr
                        dst_l2 = next_nodes[addr].get_l2_address()

        if dst_ip and dst_l2:
            packet[Ether].src = self._data.get_wifi_l2_address()
            packet[Ether].dst = dst_l2
            packet[IPv6][0].src = self._data.get_wifi_global_address()
            packet[IPv6][0].dst = dst_ip
            try:
                sendp(packet, verbose=False, iface=self.iface)
            except Exception:
                print(packet.show())
                raise Exception("end bitch")
            logging.debug('BRIDGE:sending packet using "{}"'.format(self.iface))
        else:
            print("Unknown destination address while packet sending")

    def send_icmpv6_ns(self, ip_addr: str):
        ether = Ether()
        ether.src = self._data.get_wifi_l2_address()
        ip = IPv6()
        ip.src = self._data.get_wifi_global_address()
        ip.dst = "ff02::1"
        icmp = ICMPv6ND_NS()
        icmp.tgt = ip_addr
        sendp(ether / ip / icmp, verbose=False, iface=self.iface)
        logging.debug('BRIDGE:sending neighbour solicitation for target ip "{}"'.format(ip_addr))

    def send_icmpv6_na(self, src_l2: str, src_ip: str, target_ip: str):
        ether = Ether()
        ether.src = self._data.get_wifi_l2_address()
        ether.dst = src_l2
        ip = IPv6()
        ip.src = self._data.get_wifi_global_address()
        ip.dst = src_ip
        icmp = ICMPv6ND_NA()
        icmp.tgt = target_ip
        sendp(ether / ip / icmp, verbose=False, iface=self.iface)

    def notify(self, event: Event):
        from serial_connection import SerialPacketToSendEvent
        if isinstance(event, SerialPacketToSendEvent):
            self.send_packet(event.get_event())

    def __str__(self):
        return "packet-sender"


class InterfaceListener(Thread):
    """
    Thread which listens for incoming packet on WiFi interface
    """
    def __init__(self, iface, packet_parser: Ipv6PacketParser):
        Thread.__init__(self)
        self.iface = iface
        self._packetParser = packet_parser

    def get_ipv6_packet_parser(self):
        return self._packetParser

    def run(self):
        time.sleep(5)
        socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 30)
        socks.bind((self.iface, ETH_P_ALL))
        while True:
            packet, info = socks.recvfrom(MTU)
            ether_packet = Ether(packet)
            if info[2] != socket.PACKET_OUTGOING:
                if IPv6 in ether_packet:
                    self._packetParser.parse(ether_packet)
