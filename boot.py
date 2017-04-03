from serial_connection import SlipListener, SlipSender, ContikiBootEvent
from utils.configuration_loader import ConfigurationLoader
from data import Data
import configparser
import os


class Boot(object):
    _pwd = os.getcwd()

    def __init__(self):
        self._load_config()
        self._load_services()
        self._boot_event_subscribers()

    def _load_config(self):
        self.configLoader = ConfigurationLoader(configparser.ConfigParser())

    def _load_services(self):
        self._data = Data(self.configLoader.read_configuration("{0}/configuration/configuration.conf".format(self._pwd)))
        self._slip_sender = SlipSender(self._data.get_configuration()['serial']['device'])
        self._slip_listener = SlipListener(self._data.get_configuration()['serial']['device'], self._data)

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
