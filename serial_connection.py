from threading import Thread
from data import Data
from event_system import EventProducer, Event, EventListener
import logging
import serial


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


class InputParser(EventProducer):
    def __init__(self, data: Data):
        EventProducer.__init__(self)
        self._data = data
        self.add_event_support(ContikiBootEvent)
        self.add_event_support(SlipPacketToSendEvent)

    def parse(self, line):
        if line[:2] == b'!r':
            line = line.decode("utf-8")
            addresses = line[2:-1].split(';')
            for address in addresses:
                if address[:4] != "fe80" and address != "":
                    self._data.set_src_ip(address)
                    logging.info('BRIDGE:contiki uses global IPv6 address "{}"'.format(address))
        elif line[:2] == b'!p':
            print(line)
            self.notify_listeners(SlipPacketToSendEvent(line))
            logging.debug('BRIDGE:incoming packet to send')
        elif line[:2] == b'!b':
            self.notify_listeners(ContikiBootEvent(line))
            logging.info('BRIDGE:contiki is rebooting')
        else:
            logging.debug('CONTIKI:{}'.format(line))


class SlipListener(Thread):
    def __init__(self, device: str, data: Data):
        Thread.__init__(self)
        self._device = device
        self._input_parser = InputParser(data)

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
