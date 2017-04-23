import logging
import netifaces
import os
from ipaddress import IPv6Address, IPv6Network, AddressValueError
from event_system import EventProducer, Event, EventListener


class PacketBuffEvent(Event):
    def __init__(self, data: dict):
        Event.__init__(self, data)

    def __str__(self):
        return "packet-buff-event"


class PacketBuffer(EventProducer, EventListener):       # todo create packet buffer maximum limit
    def __init__(self):
        from serial_connection import SlipPacketToSendEvent
        self.counter = 1
        self.rpl_sent = 0
        self.wifi_sent = 0
        self.wrong = 0
        self._packets = {}
        EventListener.__init__(self)
        EventProducer.__init__(self)
        self.add_event_support(PacketBuffEvent)
        self.add_event_support(SlipPacketToSendEvent)

    def add_packet(self, packet: str):
        self._packets.update({
            self.counter: packet
        })
        self.notify_listeners(PacketBuffEvent({
            "id": self.counter,
            "packet": packet
        }))
        self.counter += 1

    def handle_packet(self, id: int, response: bool):
        from serial_connection import SlipPacketToSendEvent
        if id in self._packets:
            if response:
                self.notify_listeners(SlipPacketToSendEvent(self._packets[id]))
                self.wifi_sent += 1
            else:
                self.rpl_sent += 1
            del self._packets[id]
        else:
            self.wrong += 1

    def notify(self, event: Event):
        from interface_listener import RootPacketForwardEvent
        from serial_connection import ResponseToPacketRequest
        if isinstance(event, RootPacketForwardEvent):
            self.add_packet(event.get_event())
        if isinstance(event, ResponseToPacketRequest):
            self.handle_packet(event.get_event()["question_id"], event.get_event()["response"])

    def __str__(self):
        return "packet-buffer"

    def print_buffer_stats(self):
        print("Waiting packets: {}\nSent wifi: {}\nSent rpl: {}\nWrong: {}\n".format(
            len(self._packets), self.wifi_sent, self.rpl_sent, self.wrong))


class ChangeModeEvent(Event):
    def __init__(self, data: int):
        Event.__init__(self, data)

    def __str__(self):
        return "change-mode-event"


class Data(EventProducer):
    MODE_ROOT = 1
    MODE_NODE = 2

    def __init__(self, configuration):
        EventProducer.__init__(self)
        self.add_event_support(ChangeModeEvent)
        self._mote_global_address = None
        self._mote_link_local_address = None
        self._wifi_global_address = None
        self._wifi_l2_address = None
        self._mode = None
        self._configuration = configuration

    def set_mode(self, mode: int):
        if (mode == self.MODE_NODE or mode == self.MODE_ROOT) and mode != self._mode:
            self._mode = mode
            self.notify_listeners(ChangeModeEvent(mode))

    def set_wifi_global_address(self, global_address):
        self._wifi_global_address = global_address

    def get_wifi_global_address(self):
        return self._wifi_global_address

    def set_wifi_l2_address(self, address):
        self._wifi_l2_address = address

    def get_wifi_l2_address(self):
        return self._wifi_l2_address

    def set_mote_global_address(self, global_address):
        self._mote_global_address = global_address

    def get_mote_global_address(self):
        return self._mote_global_address

    def set_mote_link_local_address(self, link_local_address):
        self._mote_link_local_address = link_local_address

    def get_mote_link_local_address(self):
        return self._mote_link_local_address

    def get_configuration(self):
        return self._configuration

    def get_mode(self):
        return self._mode

    def print_data(self):
        print('Bridge mode: {}\nMote global IP: {:>30}\nMote local IP: {:>30}\nWifi global IP: {:>30}\nWifi MAC{:>30}\n'.
              format("ROOT" if self._mode == self.MODE_ROOT else "NODE", self._mote_global_address,
                     self._mote_link_local_address, self._wifi_global_address, self._wifi_l2_address))


class IpConfigurator(EventListener):
    """
    Class responsible for interface configuration
    """

    def __init__(self, data: Data, iface: str, prefix: str, root_address: str):
        self._iface = iface
        self._data = data
        self._root_address = root_address
        self._prefix = IPv6Network(prefix)

    def _add_route(self, address: str):
        logging.debug('BRIDGE:adding route to "{}" via "{}" interface'.format(address, self._iface))
        os.system("ip -6 route add {} dev {}".format(address, self._iface))

    def _remove_route(self, address: str):
        logging.debug('BRIDGE:removing route to "{}" via "{}" interface'.format(address, self._iface))
        os.system("ip -6 route del {} dev {}".format(address, self._iface))

    def _set_address(self, address: str):
        logging.debug('BRIDGE:adding address "{}" to "{}" interface'.format(address, self._iface))
        os.system("ifconfig {} add {}".format(self._iface, address))

    def _unset_address(self, address: str):
        logging.debug('BRIDGE:removing address "{}" from "{}" interface'.format(address, self._iface))
        os.system("ifconfig {} del {}".format(self._iface, address))

    def _get_wifi_global_addressees(self):
        interface = netifaces.ifaddresses(self._iface)
        try:
            return interface[netifaces.AF_INET6]
        except KeyError:
            logging.debug('BRIDGE:previous ipv6 address not configured for "{}" interface'.format(self._iface))
        return []

    def _remove_current_addresses_from_prefix(self, current_addresses: list):
        for address in current_addresses:
            try:
                addr_obj = IPv6Address(address['addr'])
                if addr_obj in self._prefix:
                    self._unset_address("{}/{}".format(str(addr_obj), self._prefix.prefixlen))
            except AddressValueError:
                logging.warning('BRIDGE:interface "{}" has not valid ipv6 address "{}"'.format(self._iface, address))

    """
    Gets last ocet from mote global address and concatenates it with configured prefix (new wifi global IPv6 address).
    If new address is same as previously configured address, ends. Else, removes old global IPv6 address. Result sets
    up as wifi global IPv6 address, sets up routes.
    """
    def set_wifi_ipv6_lobal_address(self, mote_global_address: str):
        last_ocet = mote_global_address.split(":")[-1]
        wifi_global_address = str(self._prefix).replace("::", "::{}".format(last_ocet))

        if wifi_global_address == self._data.get_wifi_global_address():
            return

        current_addresses = self._get_wifi_global_addressees()
        self._remove_current_addresses_from_prefix(current_addresses)

        if wifi_global_address != self._data.get_wifi_global_address():
            self._set_address(wifi_global_address)
            self._data.set_wifi_global_address(wifi_global_address.split("/")[0])
        self._add_route("default")

    def load_wifi_l2_address(self):
        l2_addr = netifaces.ifaddresses(self._iface)[netifaces.AF_LINK][0]['addr']
        self._data.set_wifi_l2_address(l2_addr)

    def notify(self, event: Event):
        from serial_connection import SettingMoteGlobalAddressEvent
        if isinstance(event, SettingMoteGlobalAddressEvent):
            self.set_wifi_ipv6_lobal_address(event.get_event())
        elif isinstance(event, ChangeModeEvent):
            mode = event.get_event()
            if mode == Data.MODE_NODE:
                self._unset_address(self._root_address)
                self._add_route(self._root_address)
            elif mode == Data.MODE_ROOT:
                self._set_address(self._root_address)
                self._remove_route(self._root_address)

    def __str__(self):
        return "ip-configurator"


