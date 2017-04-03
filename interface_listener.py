from threading import Thread
from data import Data
from event_system import EventListener, Event
from serial_connection import SlipPacketToSendEvent
import time
from scapy.all import ETH_P_ALL
from scapy.all import MTU
import socket
from scapy.all import *


class InterfaceListener(Thread, EventListener):
    def __init__(self, iface, data: Data):
        Thread.__init__(self)
        self.iface = iface
        self._data = data

    def run(self):
        time.sleep(5)
        socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 30)
        socks.bind((self.iface, ETH_P_ALL))
        while True:
            packet, info = socks.recvfrom(MTU)
            ether_packet = Ether(packet)
            if info[2] != socket.PACKET_OUTGOING:
                None
                # print(ether_packet)

    def notify(self, event: Event):     # todo refactor, move packet creation to another service
        if isinstance(event, SlipPacketToSendEvent):
            packet_to_send = event.get_event()
            print("sending packet: {}".format(packet_to_send[2:-1]))

            packet_to_send_decoded = packet_to_send[2:-1].decode("utf-8")
            values = packet_to_send_decoded.split(";")
            print(values)

            ip_w = IPv6()
            ip_w.dst = self._data.get_configuration()['border-router']['ipv6']
            ip_r = IPv6()
            ip_r.src = self._data.get_src_ip().decode("utf-8")
            ip_r.dst = values[0]
            udp = UDP()
            udp.sport = int(values[1])
            udp.dport = int(values[2])
            send(ip_w/ip_r/udp/values[3])

    def __str__(self):
        return "interface-listener"
