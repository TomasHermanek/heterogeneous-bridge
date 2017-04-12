from serial_connection import SlipListener, SlipSender, ContikiBootEvent, SlipPacketToSendEvent, SlipCommands, \
    InputParser, SettingMoteGlobalAddressEvent
from timers import NeighbourRequestTimer, PurgeTimer
from interface_listener import InterfaceListener, Ipv6PacketParser, IncomingPacketSendToSlipEvent, PacketSender, \
    MoteNeighbourSolicitationEvent
from utils.configuration_loader import ConfigurationLoader
from data import Data, NodeTable, NewNodeEvent, IpConfigurator
import configparser
import os
import logging


class Boot(object):
    _pwd = os.getcwd()
    _tech_types = ['wifi', 'rpl']

    def __init__(self):
        logging.basicConfig(filename='prod.log', level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        os.chmod("prod.log", 436)
        logging.info('BRIDGE:starting bridge')

        self._load_config()
        self._load_services()
        self._boot_event_subscribers()

    def _load_config(self):
        self.configLoader = ConfigurationLoader(configparser.ConfigParser())

    def _load_services(self):   # todo create service container instead of variables -> create configuration file for loading?
        self._data = Data(self.configLoader.read_configuration(
            "{0}/configuration/configuration.conf".format(self._pwd)))
        self._node_table = NodeTable(self._tech_types)
        self._slip_sender = SlipSender(self._data.get_configuration()['serial']['device'])
        self._input_parser = InputParser(self._data, self._node_table)
        self._slip_listener = SlipListener(self._data.get_configuration()['serial']['device'], self._data,
                                           self._input_parser)
        self._packet_parser = Ipv6PacketParser(self._data)
        self._interface_listener = InterfaceListener(self._data.get_configuration()['wifi']['device'], self._packet_parser)
        self._slip_commands = SlipCommands(self._slip_sender, self._data)
        self._packed_sender = PacketSender(self._data.get_configuration()['wifi']['device'], self._data)
        self._neighbour_request_timer = NeighbourRequestTimer(10, self._slip_commands)
        self._ip_configurator = IpConfigurator(self._data.get_configuration()['wifi']['device'],
                                               self._data.get_configuration()['wifi']['subnet'])
        self._purge_timer = PurgeTimer(1, self._node_table)

    def _boot_event_subscribers(self):
        self._input_parser.subscribe_event(ContikiBootEvent, self._slip_commands)
        self._input_parser.subscribe_event(SlipPacketToSendEvent, self._packed_sender)
        self._interface_listener.get_ipv6_packet_parser().subscribe_event(IncomingPacketSendToSlipEvent,
                                                                          self._slip_commands)
        self._node_table.subscribe_event(NewNodeEvent, self._packed_sender)
        self._packet_parser.subscribe_event(MoteNeighbourSolicitationEvent, self._packed_sender)
        self._input_parser.subscribe_event(SettingMoteGlobalAddressEvent, self._ip_configurator)

    def run(self):
        try:
            self._slip_listener.start()
            self._interface_listener.start()
            self._neighbour_request_timer.start()
            self._purge_timer.start()
        except:
            print("Error: unable to start thread")

        self._slip_commands.send_config_to_contiki()
        self._slip_commands.request_config_from_contiki()
        while 1:
            pass

if __name__ == '__main__':
    Boot().run()
