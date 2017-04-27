from threading import Thread
from data import Data
from neighbors import NodeAddress, NodeTable
from event_system import EventProducer, Event, EventListener
from packet import ContikiPacket
import logging
import serial
import ipaddress


class ContikiBootEvent(Event):
    def __init__(self, line: str):
        Event.__init__(self, line)

    def __str__(self):
        return "contiki-boot-event"


class SerialPacketToSendEvent(Event):
    def __init__(self, data: ContikiPacket):
        Event.__init__(self, data)

    def __str__(self):
        return "slip-packet-to-send-event"


class MoteGlobalAddressEvent(Event):
    def __init__(self, data: str):
        Event.__init__(self, data)
        logging.info('BRIDGE: contiki uses global IPv6 address "{}"'.format(data))

    def __str__(self):
        return "setting-mote-global-address-event"


class RequestRouteToMoteEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)
        logging.debug('BRIDGE: contiki needs wants to use wifi for target host "{}"'.format(data['ip_addr']))

    def __str__(self):
        return "request-route-to-mote-event"


class ResponseToPacketRequest(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "response-to-packet-request-event"


class SerialParser(EventProducer):
    """
    SerialParser is responsible for parse of data received over serial line. Data are separated into these groups:
    prints: prints from contiki in format <-printing data->
    commands: !<command>
    requests: ?<request>
    responses: $<response>
    Each message type (except prints) throws different system event
    """
    def __init__(self, data: Data, node_table: NodeTable):
        EventProducer.__init__(self)
        self._data = data
        self._node_table = node_table
        self.add_event_support(ContikiBootEvent)
        self.add_event_support(SerialPacketToSendEvent)
        self.add_event_support(MoteGlobalAddressEvent)
        self.add_event_support(RequestRouteToMoteEvent)
        self.add_event_support(ResponseToPacketRequest)
        self._reading_print = False

    def parse(self, line):
        if line[:2] == b'<-':
            self._reading_print = True
            print("\n")
        elif line[:2] == b'->':
            self._reading_print = False
        elif self._reading_print:
            print(line.decode("UTF-8", "ignore")[:-1])
        # sends contiki addresses
        elif line[:2] == b'!r':
            line = line.decode("UTF-8", "ignore")
            addresses = line[2:-1].split(';')
            for address in addresses:
                if address != "":
                    ipadress_obj = ipaddress.ip_address(address)
                    if ipadress_obj.is_global:
                        self._data.set_mote_global_address(address)
                        self.notify_listeners(MoteGlobalAddressEvent(address))
                    elif ipadress_obj.is_link_local:
                        self._data.set_mote_link_local_address(address)
        # asking if device is possible to deliver packet using wifi
        elif line[:2] == b'?p':
            line = line.decode("UTF-8", "ignore")
            (question_id, ip_addr) = line[3:-1].split(";")
            self.notify_listeners(RequestRouteToMoteEvent({
                "question_id": question_id,
                "ip_addr": ip_addr
            }))
        elif line[:2] == b'$p':
            line = line.decode("UTF-8", "ignore")
            try:
                values = line[3:].split(";")
            except ValueError:
                print("Error in line split\n", (line[3:].split(";")))
                print("Line {}\n".format(line))
                return
            self.notify_listeners(ResponseToPacketRequest({
                "question_id": int(values[0]),
                "response": True if values[1] == "1" else False
            }))
        elif line[:2] == b'!p':
            contiki_packet = ContikiPacket()
            contiki_packet.set_contiki_format(line[3:-1])
            self.notify_listeners(SerialPacketToSendEvent(contiki_packet))
            logging.debug('BRIDGE:incoming packet to send')
        elif line[:2] == b'!b':
            self.notify_listeners(ContikiBootEvent(line))
            logging.info('BRIDGE:contiki is rebooting')
        elif line[:2] == b'!c':
            self._data.set_mode(int(line[2:-1]))
            logging.info('BRIDGE:bridge runs in mode {}'.format(line[2:-1]))
        elif line[:2] == b'!n':
            line = line.decode("UTF-8", "ignore")
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
            print(line)
            logging.debug('CONTIKI:{}'.format(line))


class SerialListener(Thread):
    """
    This thread is responsible for creating connection over serial line. After that, each received line is passed to
    SerialParser for handle data.
    """
    def __init__(self, device: str, serial_parser: SerialParser):
        Thread.__init__(self)
        self._device = device
        self._serial_parser = serial_parser

    def get_input_parser(self):
        return self._serial_parser

    def run(self):
        ser = serial.Serial(port=self._device, baudrate=115200, parity=serial.PARITY_NONE,
                            stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)
        logging.info('BRIDGE:connected to serial device "{}"'.format(self._device))
        while True:
            line = ser.readline()
            if line:
                self._serial_parser.parse(line)


class SerialSender:
    def __init__(self, device: str):
        self._ser = serial.Serial(port=device, baudrate=115200, parity=serial.PARITY_NONE,
                                  stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)

    def send(self, msg: bytes):
        self._ser.write(msg)
        # print(msg)


class SerialCommands(EventListener):
    def __init__(self, slip_sender: SerialSender, data: Data):
        self._slip_sender = slip_sender
        self._data = data

    def print_flows_request(self):
        self._slip_sender.send(str.encode("#f"))

    def print_metrics_request(self):
        self._slip_sender.send(str.encode("#m"))

    def print_statistics(self):
        self._slip_sender.send(str.encode("#s"))

    def send_config_to_contiki(self):
        metrics = self._data.get_configuration()['metrics']
        cmd = "!we{}b{}x{}\n".format(metrics['en'], metrics['bw'], metrics['etx'])
        self._slip_sender.send(str.encode(cmd))
        logging.info('BRIDGE:sending config "{}" to contiki'.format(cmd))

    def send_route_request_response_to_contiki(self, question_id: int, response: int):
        cmd = "$p;{};{}".format(question_id, response)
        self._slip_sender.send(str.encode(cmd))
        logging.info('BRIDGE:sending response to route request "{}"'.format(cmd))

    def request_config_from_contiki(self):
        self._slip_sender.send(b'?c\n')
        logging.info('BRIDGE:requesting configuration from contiki')

    def request_neighbours_from_contiki(self):
        self._slip_sender.send(b'?n\n')
        logging.info('BRIDGE:requesting neighbours from contiki')

    def request_forward_packet_decision(self, id: int, contiki_packet: ContikiPacket):
        self._slip_sender.send(str.encode("?p;{};{}\n".format(id, contiki_packet.get_contiki_format())))
        # print("sending: {}\n".format("?p;{};{}\n".format(id, raw_packet)))
        logging.info('BRIDGE:requesting forward decision')

    def send_packet_to_contiki(self, contiki_packet: ContikiPacket):
        self._slip_sender.send(str.encode("!p;{}\n".format(contiki_packet.get_contiki_format())))
        logging.debug('BRIDGE:sending packet to contiki')

    def forward_packet_to_contiki(self, contiki_packet: ContikiPacket):
        self._slip_sender.send(str.encode("!f;{}\n".format(contiki_packet.get_contiki_format())))
        logging.debug('BRIDGE:forwarding packet to contiki')

    def notify(self, event: Event):
        from interface_listener import PacketSendToSerialEvent, PacketForwardToSerialEvent
        from data import PacketBuffEvent
        if isinstance(event, ContikiBootEvent):
            self.send_config_to_contiki()
        elif isinstance(event, PacketSendToSerialEvent):
            self.send_packet_to_contiki(event.get_event())
        elif isinstance(event, PacketForwardToSerialEvent):
            self.forward_packet_to_contiki(event.get_event())
        elif isinstance(event, PacketBuffEvent):
            self.request_forward_packet_decision(event.get_event()["id"], event.get_event()["packet"])

    def __str__(self):
        return "slip-commands"
