from threading import Thread
from data import Data
from event_system import EventProducer, Event, EventListener
import serial


class ContikiBootEvent(Event):
    def __init__(self, entry: str):
        Event.__init__(self, entry)

    def __str__(self):
        return "rpl-update-table-event"


class InputParser(EventProducer):
    def __init__(self, data: Data):
        EventProducer.__init__(self)
        self._data = data
        self.add_event_support(ContikiBootEvent)

    def parse(self, line):
        if line[:2] == b'!r':
            self._data.set_src_ip(line[2:-1])
        elif line[:2] == b'!p':
            print("sending packet: {}".format(line[2:-1]))
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


class SlipSender(EventListener):
    def __init__(self, device: str):
        self._ser = serial.Serial(port=device, baudrate=115200, parity=serial.PARITY_NONE,
                                  stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=0)

    def send(self, msg: bytes):
        self._ser.write(msg)

    def notify(self, event: Event):
        print("event\n")
        if isinstance(event, ContikiBootEvent):
            print("contiki boot event")
            self.send(b'!we40b1x5\n')                       # todo refactor this
