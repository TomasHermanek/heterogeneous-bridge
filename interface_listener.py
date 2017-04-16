from threading import Thread

from scapy.all import *

from data import Data
from event_system import EventListener, Event, EventProducer


class IncomingPacketSendToSlipEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "incoming-packet-to-slip-event"


class MoteNeighbourSolicitationEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "mote-neighbour-solicitation-event"


class NeighbourAdvertisementEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "neighbour-advertisement-event"


class Ipv6PacketParser(EventProducer):
    def __init__(self, data: Data):
        EventProducer.__init__(self)
        self._data = data
        self.add_event_support(IncomingPacketSendToSlipEvent)
        self.add_event_support(MoteNeighbourSolicitationEvent)
        self.add_event_support(NeighbourAdvertisementEvent)

    """
    Packed sent from another mote via WIFI must contains two IP headers, first one is used by internal WIFI, but second
    one contains motes global IPv6 address
    """
    def _parse_udp(self, packet: Ether):
        ip = packet[IPv6]
        # print("comparing {} vs {}".format(ip[1].dst, self._data.get_src_ip()))
        if ip[1].dst == self._data.get_mote_global_address():
            # print("target is my mote")
            udp = packet[UDP]
            raw = packet[Raw]
            src_addr = ipaddress.ip_address(ip[1].src)
            dst_addr = ipaddress.ip_address(ip[1].dst)
            contiki_packet = "{};{};{};{};{}".format(src_addr.exploded, dst_addr.exploded, udp.sport, udp.dport,
                                                     raw.load.decode("utf-8"))
            self.notify_listeners(IncomingPacketSendToSlipEvent(contiki_packet))

    def _parse_icmpv6_ns(self, packet: Ether):      # refactor - add this to neighbour manager
        target_ip = packet[ICMPv6ND_NS].tgt
        src_ip = packet[IPv6].src

        if str(self._data.get_mote_global_address()) == target_ip or str(self._data.get_mote_link_local_address()) == target_ip:
            logging.warning('BRIDGE:Sending response to ICMPv6 neighbour solicitation for address "{}"'
                            .format(target_ip))
            self.notify_listeners(MoteNeighbourSolicitationEvent({
                "src_ip": src_ip,
                "target_ip": target_ip
            }))

    def _parse_icmpv6_na(self, packet: Ether):
        target_ip = packet[ICMPv6ND_NA].tgt
        src_ip = packet[IPv6].src
        self.notify_listeners(NeighbourAdvertisementEvent({
            "src_ip": src_ip,
            "target_ip": target_ip
        }))

    def parse(self, packet: Ether):
        if not self._data.get_mote_global_address():
            logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not compare incoming packet')
            return
        if IPv6 in packet and UDP in packet:
            try:
                self._parse_udp(packet)
            except Exception as e:
                logging.error('BRIDGE:{}'.format(str(e)))
        if ICMPv6ND_NS in packet:
            self._parse_icmpv6_ns(packet)
        if ICMPv6ND_NA in packet:
            self._parse_icmpv6_na(packet)


class PacketSender(EventListener):
    def __init__(self, iface, data: Data):
        self.iface = iface
        self._data = data

    def _packet_send_to_root(self, packet: str):
        values = packet.split(";")
        ip_w = IPv6()
        ip_w.src = self._data.get_wifi_global_address()
        ip_w.dst = self._data.get_configuration()['border-router']['ipv6']
        ip_r = IPv6()
        ip_r.src = self._data.get_mote_global_address()
        ip_r.dst = values[0]
        udp = UDP()
        udp.sport = int(values[1])
        udp.dport = int(values[2])
        send(ip_w / ip_r / udp / values[3], verbose=False)
        logging.debug('BRIDGE:sending packet using "{}"'.format(self.iface))

    def send_icmpv6_ns(self, ip_addr: str):
        ip = IPv6()
        ip.src = self._data.get_wifi_global_address()
        # print("sending icmp using global ip {}".format(self._data.get_wifi_global_address()))
        ip.dst = "ff02::1"
        icmp = ICMPv6ND_NS()
        icmp.tgt = ip_addr
        send(ip / icmp, verbose=False)
        logging.debug('BRIDGE:sending neighbour solicitation for target ip "{}"'.format(ip_addr))

    def send_icmpv6_na(self, src_ip: str, target_ip: str):
        ip = IPv6()
        ip.src = self._data.get_wifi_global_address()
        ip.dst = src_ip
        icmp = ICMPv6ND_NA()
        icmp.tgt = target_ip
        send(ip / icmp, verbose=False)

    def notify(self, event: Event):
        from serial_connection import SlipPacketToSendEvent
        if isinstance(event, SlipPacketToSendEvent):
            if not self._data.get_mote_global_address():
                logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not send packet')
                return

            packet_to_send = event.get_event()
            packet_to_send_decoded = packet_to_send[2:-1].decode("utf-8")
            self._packet_send_to_root(packet_to_send_decoded)

    def __str__(self):
        return "packet-sender"


class InterfaceListener(Thread):
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
