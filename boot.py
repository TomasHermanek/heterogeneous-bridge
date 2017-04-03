from serial_connection import SlipListener, SlipSender, ContikiBootEvent
from data import Data


class Boot(object):
    def __init__(self):
        self._data = Data()
        self._slip_sender = SlipSender('/dev/ttyUSB0')
        self._slip_listener = SlipListener('/dev/ttyUSB0', self._data)

        self._boot_event_subscribers()

    def _boot_event_subscribers(self):
        self._slip_listener.get_input_parser().subscribe_event(ContikiBootEvent, self._slip_sender)

    def run(self):
        self._slip_sender.send(b'!we40b1x5\n')
        try:
            self._slip_listener.start()
        except:
            print("Error: unable to start thread")

        while 1:
            pass

if __name__ == '__main__':
    Boot().run()
