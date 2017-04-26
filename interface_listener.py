from threading import Thread
from scapy.all import *
from data import Data
from event_system import EventListener, Event, EventProducer


class PacketSendToSerialEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "incoming-packet-to-slip-event"


class PacketForwardToSerialEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "packet-forward-to-serial-event"


class NeighbourSolicitationEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "mote-neighbour-solicitation-event"


class NeighbourAdvertisementEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "neighbour-advertisement-event"


class RootPacketForwardEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "root-packet-forward"


class Ipv6PacketParser(EventProducer):
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
        ip = packet[IPv6]
        udp = packet[UDP]
        raw = packet[Raw]
        src_addr = ipaddress.ip_address(ip[1].src)
        dst_addr = ipaddress.ip_address(ip[1].dst)
        contiki_packet = "{};{};{};{};{}".format(src_addr.exploded, dst_addr.exploded, udp.sport, udp.dport,
                                                 raw.load.decode("UTF-8", "ignore"))

        if self._data.get_mode() == Data.MODE_ROOT and ip[0].dst == self._data.get_configuration()['border-router']['ipv6']:
            ask = False
            node_address = self._node_table.get_node_address(ip[1].dst, 'rpl')
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
        if str(self._data.get_mote_global_address()) == target_ip or str(self._data.get_mote_link_local_address()) == target_ip:
            logging.warning('BRIDGE:Sending response to ICMPv6 neighbour solicitation for address "{}"'
                            .format(target_ip))
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
                self._parse_udp(packet)
            except Exception as e:
                logging.error('BRIDGE:{}'.format(str(e)))
        if ICMPv6ND_NS in packet:
            self._parse_icmpv6_ns(packet)
        if ICMPv6ND_NA in packet:
            self._parse_icmpv6_na(packet)


class PacketSender(EventListener):
    def __init__(self, iface, data: Data, node_table):
        self.iface = iface
        self._data = data
        self._node_table = node_table

    def send_packet(self, packet: str):
        values = packet.split(";")
        dst_ip = None
        dst_l2 = None
        if self._data.get_mode() == Data.MODE_NODE:
            dst_ip = self._data.get_configuration()['border-router']['ipv6']
            dst_l2 = "33:33:00:00:00:fb"        # todo check if it is correct
        else:
            node = self._node_table.get_node_address(values[1], 'rpl')
            if node:
                next_nodes = node.get_node_addresses()
                for addr in next_nodes:
                    if next_nodes[addr].get_tech_type() == "wifi":
                        dst_ip = addr
                        dst_l2 = next_nodes[addr].get_l2_address()

        if dst_ip and dst_l2:
            # print("{}{}/{}{}/{}\n".format(self._data.get_wifi_global_address(), dst_ip, values[0], values[1], values[4]))
            ether = Ether()
            ether.src = self._data.get_wifi_l2_address()
            ether.dst = dst_l2
            ip_w = IPv6()
            ip_w.src = self._data.get_wifi_global_address()
            ip_w.dst = dst_ip
            ip_r = IPv6()
            ip_r.src = values[0]
            ip_r.dst = values[1]
            udp = UDP()
            udp.sport = int(values[2])
            udp.dport = int(values[3])
            try:
                # packet = ether / ip_w / ip_r / udp / values[4]
                # print(packet.show())
                sendp(ether / ip_w / ip_r / udp / values[4], verbose=False, iface=self.iface)
            except Exception:
                packet = ether / ip_w / ip_r / udp / values[4]
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
        # print("sending icmp using global ip {}".format(self._data.get_wifi_global_address()))
        ip.dst = "ff02::1"
        icmp = ICMPv6ND_NS()
        icmp.tgt = ip_addr
        sendp(ether / ip / icmp, verbose=False, iface=self.iface)
        logging.debug('BRIDGE:sending neighbour solicitation for target ip "{}"'.format(ip_addr))

    def send_icmpv6_na(self, src_l2: str, src_ip: str, target_ip: str):
        ether = Ether()
        ether.src = self._data.get_wifi_l2_address()
        ether.dst = src_l2
        # print("sending NA: srcip: {} target_ip:{} global_{}".format(src_ip, target_ip, self._data.get_wifi_global_address()))
        ip = IPv6()
        ip.src = self._data.get_wifi_global_address()
        ip.dst = src_ip
        icmp = ICMPv6ND_NA()
        icmp.tgt = target_ip
        sendp(ether / ip / icmp, verbose=False, iface=self.iface)

    def notify(self, event: Event):
        from serial_connection import SerialPacketToSendEvent
        if isinstance(event, SerialPacketToSendEvent):
            # if not self._data.get_mote_global_address():
            #     logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not send packet')
            #     return
            # packet_to_send = event.get_event()
            # packet_to_send_decoded = packet_to_send[3:-1].decode("UTF-8", "ignore")
            self.send_packet(event.get_event())

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
