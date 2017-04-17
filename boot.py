from serial_connection import SlipListener, SlipSender, ContikiBootEvent, SlipPacketToSendEvent, SlipCommands, \
    InputParser, SettingMoteGlobalAddressEvent, RequestRouteToMoteEvent, ResponseToPacketRequest
from timers import NeighbourRequestTimer, PurgeTimer
from interface_listener import InterfaceListener, Ipv6PacketParser, IncomingPacketSendToSlipEvent, PacketSender, \
    MoteNeighbourSolicitationEvent, NeighbourAdvertisementEvent, RootPacketForwardEvent
from neighbors import PendingSolicitations, NewNodeEvent, NodeTable, NodeRefreshEvent
from utils.configuration_loader import ConfigurationLoader
from data import Data, IpConfigurator, ChangeModeEvent, PacketBuffer, PacketBuffEvent
from neighbors import NeighborManager
from command_listener import CommandListener, Command
import configparser
import os
import time
import logging


class Boot(object):
    _pwd = os.getcwd()
    _tech_types = ['wifi', 'rpl']

    def __init__(self):
        logging.basicConfig(filename='prod.log', level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p')
        logging.info('BRIDGE:starting bridge')
        logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

        self._load_config()
        self._load_services()
        self._boot_event_subscribers()
        self._load_commands()

    def _load_config(self):
        self.configLoader = ConfigurationLoader(configparser.ConfigParser())

    def _load_services(self):   # todo create service container instead of variables -> create configuration file for loading?
        self._data = Data(self.configLoader.read_configuration(
            "{0}/configuration/configuration.conf".format(self._pwd)))
        self._node_table = NodeTable(self._tech_types)
        self._pending_solicitations = PendingSolicitations()
        self._slip_sender = SlipSender(self._data.get_configuration()['serial']['device'])
        self._input_parser = InputParser(self._data, self._node_table)
        self._slip_listener = SlipListener(self._data.get_configuration()['serial']['device'], self._data,
                                           self._input_parser)
        self._packet_parser = Ipv6PacketParser(self._data, self._node_table)
        self._interface_listener = InterfaceListener(self._data.get_configuration()['wifi']['device'], self._packet_parser)
        self._slip_commands = SlipCommands(self._slip_sender, self._data)
        self._packed_sender = PacketSender(self._data.get_configuration()['wifi']['device'], self._data, self._node_table)
        self._neighbour_manager = NeighborManager(self._node_table, self._data, self._pending_solicitations, self._packed_sender, self._slip_commands)
        self._neighbour_request_timer = NeighbourRequestTimer(10, self._slip_commands)
        self._ip_configurator = IpConfigurator(self._data, self._data.get_configuration()['wifi']['device'],
                                               self._data.get_configuration()['wifi']['subnet'],
                                               self._data.get_configuration()['border-router']['ipv6'])
        self._purge_timer = PurgeTimer(1, self._node_table)
        self._command_listener = CommandListener()
        self._packet_buffer = PacketBuffer()

    def _boot_event_subscribers(self):
        self._input_parser.subscribe_event(ContikiBootEvent, self._slip_commands)
        self._input_parser.subscribe_event(SlipPacketToSendEvent, self._packed_sender)
        self._interface_listener.get_ipv6_packet_parser().subscribe_event(IncomingPacketSendToSlipEvent,
                                                                          self._slip_commands)
        self._node_table.subscribe_event(NewNodeEvent, self._neighbour_manager)
        self._node_table.subscribe_event(NodeRefreshEvent, self._neighbour_manager)
        self._packet_parser.subscribe_event(MoteNeighbourSolicitationEvent, self._neighbour_manager)
        self._packet_parser.subscribe_event(NeighbourAdvertisementEvent, self._neighbour_manager)
        self._packet_parser.subscribe_event(RootPacketForwardEvent, self._packet_buffer)
        self._input_parser.subscribe_event(SettingMoteGlobalAddressEvent, self._ip_configurator)
        self._input_parser.subscribe_event(RequestRouteToMoteEvent, self._neighbour_manager)
        self._data.subscribe_event(ChangeModeEvent, self._ip_configurator)
        self._packet_buffer.subscribe_event(PacketBuffEvent, self._slip_commands)
        self._input_parser.subscribe_event(ResponseToPacketRequest, self._packet_buffer)

    def _load_commands(self):
        self._command_listener.add_command(Command("node", self._node_table.print_table, "Shows node table"))
        self._command_listener.add_command(Command("metric", self._slip_commands.print_metrics_request,
                                                   "Shows metrics table"))
        self._command_listener.add_command(Command("flow", self._slip_commands.print_flows_request, "Shows flow table"))
        self._command_listener.add_command(Command("data", self._data.print_data, "Prints bridge internal data"))
        self._command_listener.add_command(Command("pending", self._pending_solicitations.print_pendings,
                                                   "Prints ICMPv6 pending"))
        self._command_listener.add_command(Command("buffer", self._packet_buffer.print_buffer_stats,
                                                   "Shows packet buffer stats"))

    def run(self):
        try:
            self._slip_listener.start()
        except:
            print("Error: unable to start thread")

        self._data.set_mode(Data.MODE_NODE)
        self._slip_commands.request_config_from_contiki()
        self._slip_commands.send_config_to_contiki()

        print("Loading")
        while not self._data.get_mote_global_address():
            print(".")
            time.sleep(1)
        print("Configuration loaded, loading listeners")
        try:
            self._interface_listener.start()
            self._neighbour_request_timer.start()
            self._purge_timer.start()
            print("Listeners loaded, starting command line")
            self._command_listener.start()
        except:
            print("Error: unable to start thread")
        while 1:
            pass

if __name__ == '__main__':
    Boot().run()
