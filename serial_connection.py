from threading import Thread
from data import Data, NodeAddress, NodeTable
from event_system import EventProducer, Event, EventListener
import logging
import serial
import ipaddress


class ContikiBootEvent(Event):
    def __init__(self, line: str):
        Event.__init__(self, line)

    def __str__(self):
        return "contiki-boot-event"


class SlipPacketToSendEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "slip-packet-to-send-event"


class SettingMoteGlobalAddressEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)

    def __str__(self):
        return "setting-mote-global-address-event"


class InputParser(EventProducer):
    def __init__(self, data: Data, node_table: NodeTable):
        EventProducer.__init__(self)
        self._data = data
        self._node_table = node_table
        self.add_event_support(ContikiBootEvent)
        self.add_event_support(SlipPacketToSendEvent)
        self.add_event_support(SettingMoteGlobalAddressEvent)

    def parse(self, line):
        if line[:2] == b'!r':
            line = line.decode("utf-8")
            addresses = line[2:-1].split(';')
            for address in addresses:
                if address != "":
                    ipadress_obj = ipaddress.ip_address(address)
                    if ipadress_obj.is_global:
                        self._data.set_mote_global_address(address)
                        self.notify_listeners(SettingMoteGlobalAddressEvent(address))
                        logging.info('BRIDGE:contiki uses global IPv6 address "{}"'.format(address))
                    elif ipadress_obj.is_link_local:
                        self._data.set_mote_link_local_address(address)
                        logging.info('BRIDGE:contiki uses link local IPv6 address "{}"'.format(address))
        elif line[:2] == b'!p':
            self.notify_listeners(SlipPacketToSendEvent(line))
            logging.debug('BRIDGE:incoming packet to send')
        elif line[:2] == b'!b':
            self.notify_listeners(ContikiBootEvent(line))
            logging.info('BRIDGE:contiki is rebooting')
        elif line[:2] == b'!n':
            line = line.decode("utf-8")
            nodes = line[2:-1].split(';')
            for node in nodes:
                if node != "":
                    try:
                        ip_obj = ipaddress.ip_address(node)
                        node_obj = NodeAddress(ip_address=ip_obj, tech_type="rpl")
                        self._node_table.add_node_address(node_obj)
                    except ValueError:
                        logging.error('BRIDGE:neighbour ip address "{} is not valid'.format(node))

        else:
            logging.debug('CONTIKI:{}'.format(line))


class SlipListener(Thread):
    def __init__(self, device: str, data: Data, input_parser: InputParser):
        Thread.__init__(self)
        self._device = device
        self._input_parser = input_parser

    def get_input_parser(self):
        return self._input_parser

    def run(self):
        ser = serial.Serial(port=self._device, baudrate=115200, parity=serial.PARITY_NONE,
                            stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)
        logging.info('BRIDGE:connected to serial device "{}"'.format(self._device))
        while True:
            line = ser.readline()
            if line:
                self._input_parser.parse(line)


class SlipSender:
    def __init__(self, device: str):
        self._ser = serial.Serial(port=device, baudrate=115200, parity=serial.PARITY_NONE,
                                  stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)

    def send(self, msg: bytes):
        self._ser.write(msg)


class SlipCommands(EventListener):
    def __init__(self, slip_sender: SlipSender, data: Data):
        self._slip_sender = slip_sender
        self._data = data

    def send_config_to_contiki(self):
        metrics = self._data.get_configuration()['metrics']
        cmd = "!we{}b{}x{}\n".format(metrics['en'], metrics['bw'], metrics['etx'])
        self._slip_sender.send(str.encode(cmd))
        logging.info('BRIDGE:sending config "{}" to contiki'.format(cmd))

    def request_config_from_contiki(self):
        self._slip_sender.send(b'?c\n')
        logging.info('BRIDGE:requesting configuration from contiki')

    def request_neighbours_from_contiki(self):
        self._slip_sender.send(b'?n\n')
        logging.info('BRIDGE:requesting neighbours from contiki')

    def send_packet_to_contiki(self, raw_packet: str):
        self._slip_sender.send(str.encode("!p;{}\n".format(raw_packet)))
        logging.debug('BRIDGE:sending packet to contiki')

    def notify(self, event: Event):
        from interface_listener import IncomingPacketSendToSlipEvent
        if isinstance(event, ContikiBootEvent):
            self.send_config_to_contiki()
        elif isinstance(event, IncomingPacketSendToSlipEvent):
            self.send_packet_to_contiki(event.get_event())

    def __str__(self):
        return "slip-commands"
