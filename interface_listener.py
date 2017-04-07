from threading import Thread
from data import Data
from event_system import EventListener, Event, EventProducer
from serial_connection import SlipPacketToSendEvent
import time
from scapy.all import ETH_P_ALL
from scapy.all import MTU
import socket
from scapy.all import *
import logging
import ipaddress


class IncomingPacketSendToSlipEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "incoming-packet-to-slip-event"


class Ipv6PacketParser(EventProducer):
    def __init__(self, data: Data):
        EventProducer.__init__(self)
        self._data = data
        self.add_event_support(IncomingPacketSendToSlipEvent)

    """
    Packed sent from another mote via WIFI must contains two IP headers, first one is used by internal WIFI, but second
    one contains motes global IPv6 address
    """
    def _parse_udp(self, packet: Ether):
        ip = packet[IPv6]
        # print("comparing {} vs {}".format(ip[1].dst, self._data.get_src_ip()))
        if IPv6 in ip and ip[1].dst == self._data.get_src_ip():
            # print("target is my mote")
            udp = packet[UDP]
            raw = packet[Raw]
            src_addr = ipaddress.ip_address(ip[1].src)
            dst_addr = ipaddress.ip_address(ip[1].dst)
            contiki_packet = "{};{};{};{};{}".format(src_addr.exploded, dst_addr.exploded, udp.sport, udp.dport, raw.load.decode("utf-8"))
            self.notify_listeners(IncomingPacketSendToSlipEvent(contiki_packet))

    def parse(self, packet: Ether):
        if not self._data.get_src_ip():
            logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not compare incoming packet')
            return
        if UDP in packet:
            self._parse_udp(packet)


class InterfaceListener(Thread, EventListener):
    def __init__(self, iface, packet_parser: Ipv6PacketParser, data: Data):
        Thread.__init__(self)
        self.iface = iface
        self._data = data
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

    def notify(self, event: Event):     # todo refactor, move packet creation to another service
        if isinstance(event, SlipPacketToSendEvent):
            if not self._data.get_src_ip():
                logging.warning('BRIDGE:Src IPv6 address of contiki device is unknown can not send packet')
                return

            packet_to_send = event.get_event()
            print("sending packet: {}".format(packet_to_send))

            packet_to_send_decoded = packet_to_send[2:-1].decode("utf-8")
            values = packet_to_send_decoded.split(";")
            print(values)

            ip_w = IPv6()
            ip_w.dst = self._data.get_configuration()['border-router']['ipv6']
            ip_r = IPv6()
            ip_r.src = self._data.get_src_ip()
            ip_r.dst = values[0]
            udp = UDP()
            udp.sport = int(values[1])
            udp.dport = int(values[2])
            send(ip_w/ip_r/udp/values[3])
            logging.debug('BRIDGE:sending packet using "{}"'.format(self.iface))

    def __str__(self):
        return "interface-listener"
