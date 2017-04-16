import logging
import netifaces
import os
from ipaddress import IPv6Address, IPv6Network, AddressValueError

from event_system import EventProducer, Event, EventListener


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

    def print_data(self):
        print('Bridge mode: {}\nMote global IP: {:>30}\nMote local IP: {:>30}\nWifi global IP: {:>30}\n'.
              format("ROOT" if self._mode == self.MODE_ROOT else "NODE", self._mote_global_address,
                     self._mote_link_local_address, self._wifi_global_address))


class IpConfigurator(EventListener):
    def __init__(self, data: Data, iface: str, prefix: str, root_address: str):
        self._iface = iface
        self._data = data
        self._root_address = root_address
        self._prefix = IPv6Network(prefix)

    def _unset_address(self, address: str):
        logging.debug('BRIDGE:removing address "{}" from "{}" interface'.format(address, self._iface))
        os.system("ifconfig {} del {}".format(self._iface, address))

    def _set_address(self, address: str):
        logging.debug('BRIDGE:adding address "{}" to "{}" interface'.format(address, self._iface))
        os.system("ifconfig {} add {}".format(self._iface, address))

    def _get_wifi_global_address(self):
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

    def set_wifi_ipv6_lobal_address(self, mote_global_address: str):        # todo check if address to remove and address to add is not same
        current_addresses = self._get_wifi_global_address()
        self._remove_current_addresses_from_prefix(current_addresses)
        last_ocet = mote_global_address.split(":")[-1]
        wifi_global_address = str(self._prefix).replace("::", "::{}".format(last_ocet))
        if wifi_global_address != self._data.get_wifi_global_address():
            self._set_address(wifi_global_address)
            self._data.set_wifi_global_address(wifi_global_address.split("/")[0])

    def notify(self, event: Event):
        from serial_connection import SettingMoteGlobalAddressEvent
        if isinstance(event, SettingMoteGlobalAddressEvent):
            self.set_wifi_ipv6_lobal_address(event.get_event())
        elif isinstance(event, ChangeModeEvent):
            mode = event.get_event()
            if mode == Data.MODE_NODE:
                self._unset_address(self._root_address)
            elif mode == Data.MODE_ROOT:
                self._set_address(self._root_address)

    def __str__(self):
        return "ip-configurator"


