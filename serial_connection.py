from threading import Thread
from data import Data
from event_system import EventProducer, Event, EventListener
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
        elif line[:2] == b'!p':
            self.notify_listeners(SlipPacketToSendEvent(line))
        elif line[:2] == b'!b':
            self.notify_listeners(ContikiBootEvent(line))


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
        print("connected to: " + ser.portstr)
        while True:
            line = ser.readline()
            if line:
                self._input_parser.parse(line)
                print(line)


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

    def request_config_from_contiki(self):
        self._slip_sender.send(b'?c\n')

    def notify(self, event: Event):
        if isinstance(event, ContikiBootEvent):
            self.send_config_to_contiki()

    def __str__(self):
        return "slip-commands"
