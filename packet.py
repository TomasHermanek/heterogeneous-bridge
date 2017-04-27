from scapy.all import *
import ipaddress


class ContikiPacket:
    """
    Valid contiki_packet format is: <src_ip>;<dst_ip>;<src_port>;<dst_port>;<payload>
    """
    def __init__(self):
        self._contiki_format = None
        self._scapy_format = None

    @staticmethod
    def contiki_to_scapy(contiki_format: str):
        values = contiki_format.split(b";")
        packet = Ether() / IPv6() / IPv6() / UDP()
        packet[IPv6][1].src = values[0].decode("UTF-8")
        packet[IPv6][1].dst = values[1].decode("UTF-8")
        packet[UDP].sport = int(values[2].decode("UTF-8"))
        packet[UDP].dport = int(values[3].decode("UTF-8"))
        packet[UDP].payload = bytes.fromhex(values[4].decode("UTF-8"))
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