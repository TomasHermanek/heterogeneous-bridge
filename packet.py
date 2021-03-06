from scapy.all import *
import ipaddress


class ContikiPacket:
    """
    Valid contiki_packet format is: <src_ip>;<dst_ip>;<src_port>;<dst_port>;<payload>
    """
    COAP_PORT = 5683

    def __init__(self):
        self._contiki_format = None
        self._scapy_format = None

    @staticmethod
    def contiki_to_scapy(contiki_format: str):
        values = contiki_format.split(";")
        packet = Ether() / IPv6() / IPv6() / UDP()
        packet[IPv6][1].src = values[0]
        packet[IPv6][1].dst = values[1]
        # packet[UDP].sport = int(values[2])
        # packet[UDP].dport = int(values[3])
        packet[UDP].sport = ContikiPacket.COAP_PORT
        packet[UDP].dport = ContikiPacket.COAP_PORT
        packet[UDP].payload = bytes.fromhex(values[4])
        return packet

    @staticmethod
    def scapy_to_contiki(scapy_format):
        udp = scapy_format[UDP]
        raw = ''.join('{:02x}'.format(x) for x in bytes(scapy_format[UDP].payload))
        src_addr = ipaddress.ip_address(scapy_format[IPv6][1].src)
        dst_addr = ipaddress.ip_address(scapy_format[IPv6][1].dst)
        return "{};{};{};{};{}".format(src_addr, dst_addr, udp.sport, udp.dport, raw)

    def set_contiki_format(self, raw_str: str):
        self._contiki_format = raw_str

    def set_scapy_format(self, packet):
        self._scapy_format = packet

    def get_contiki_format(self):
        if not self._contiki_format:
            self._contiki_format = self.scapy_to_contiki(self._scapy_format)
        return self._contiki_format

    def get_scapy_format(self):
        if not self._scapy_format:
            self._scapy_format = self.contiki_to_scapy(self._contiki_format)
        return self._scapy_format