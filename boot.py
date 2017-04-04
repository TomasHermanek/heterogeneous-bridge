from serial_connection import SlipListener, SlipSender, ContikiBootEvent, SlipPacketToSendEvent, SlipCommands
from interface_listener import InterfaceListener, Ipv6PacketParser, IncomingPacketSendToSlipEvent
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
        self._packet_parser = Ipv6PacketParser(self._data)
        self._interface_listener = InterfaceListener(self._data.get_configuration()['wifi']['device'],
                                                     self._packet_parser, self._data)
        self._slip_commands = SlipCommands(self._slip_sender, self._data)

    def _boot_event_subscribers(self):
        self._slip_listener.get_input_parser().subscribe_event(ContikiBootEvent, self._slip_commands)
        self._slip_listener.get_input_parser().subscribe_event(SlipPacketToSendEvent, self._interface_listener)
        self._interface_listener.get_ipv6_packet_parser().subscribe_event(IncomingPacketSendToSlipEvent,
                                                                          self._slip_commands)

    def run(self):
        try:
            self._slip_listener.start()
            self._interface_listener.start()
        except:
            print("Error: unable to start thread")

        self._slip_commands.send_config_to_contiki()
        self._slip_commands.request_config_from_contiki()
        while 1:
            pass

if __name__ == '__main__':
    Boot().run()
