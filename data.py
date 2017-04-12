from event_system import EventProducer, Event, EventListener
import logging
import netifaces
import os
from ipaddress import IPv6Address, IPv6Network, AddressValueError


class Data:
    MODE_ROOT = 1
    MODE_NODE = 2

    def __init__(self, configuration):
        self._mote_global_address = None
        self._mote_link_local_address = None
        self._wifi_global_address = None
        self._mode = self.MODE_NODE
        self._configuration = configuration

    def set_mode(self, mode: int):
        if mode == self.MODE_NODE or mode == self.MODE_ROOT:
            self._mode = mode

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


class IpConfigurator(EventListener):
    def __init__(self, data: Data, iface: str, prefix: str, root_address: str):
        self._iface = iface
        self._data = data
        self._root_address = root_address
        self._prefix = IPv6Network(prefix)

    def _unset_address(self, address: str):
        logging.debug('BRIDGE:removing address "{}" from "{}" interface'.format(address, self._iface))
        os.system("ifconfig {} del {}/{}".format(self._iface, address, self._prefix.prefixlen))

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
                    self._unset_address(str(addr_obj))
            except AddressValueError:
                logging.warning('BRIDGE:interface "{}" has not valid ipv6 address "{}"'.format(self._iface, address))

    def set_wifi_ipv6_lobal_address(self, mote_global_address: str):        # todo check if address to remove and address to add is not same
        current_addresses = self._get_wifi_global_address()
        self._remove_current_addresses_from_prefix(current_addresses)
        last_ocet = mote_global_address.split(":")[-1]
        wifi_global_address = str(self._prefix).replace("::", "::{}".format(last_ocet))
        self._set_address(wifi_global_address)
        self._data.set_wifi_global_address(wifi_global_address.split("/")[0])

    def notify(self, event: Event):
        from serial_connection import SettingMoteGlobalAddressEvent, ChangeModeEvent
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


class NodeAddress:
    _reset_lifetime = 255

    def __init__(self, ip_address: IPv6Address, tech_type):
        self._ip_address = ip_address
        self._lifetime = self._reset_lifetime
        self._type = tech_type
        self._next_address = {}

    def get_ip_address(self) -> IPv6Address:
        return self._ip_address

    def get_tech_type(self) -> str:
        return self._type

    def get_lifetime(self) -> int:
        return self._lifetime

    def reset_lifetime(self):
        self._lifetime = self._reset_lifetime

    def decrease_lifetime(self):
        self._lifetime -= 1

    def add_next_node_address(self, node_address):
        if str(node_address.get_ip_address()) not in self._next_address:
            self._next_address.update({
                str(node_address.get_ip_address()): node_address
            })
            node_address.add_next_node_address(self)

    def remove_next_node_address(self, node_address):
        if str(node_address.get_ip_address()) in self._next_address:
            del self._next_address[str(node_address.get_ip_address())]
            node_address.remove_next_node_address(self)

    def get_node_addresses(self):
        return self._next_address

    def __str__(self):
        return "IP address: {}, lifetime: {}".format(str(self._ip_address), self._lifetime)


class NewNodeEvent(Event):
    def __init__(self, data: NodeAddress):
        Event.__init__(self, data)

    def __str__(self):
        return "new-node-event"


class NodeTable(EventProducer):
    def __init__(self, types: list):
        EventProducer.__init__(self)
        self.add_event_support(NewNodeEvent)
        self._nodes = {}
        self._types = types
        for tech_type in types:
            self._nodes.update({
                tech_type: {}
            })

    def node_exists(self, address: NodeAddress):
        pass # todo implement

    def add_node_address(self, node_address: NodeAddress):
        if str(node_address.get_ip_address()) not in self._nodes[node_address.get_tech_type()]:
            self._nodes[node_address.get_tech_type()].update({
                str(node_address.get_ip_address()): node_address
            })
            logging.debug('BRIDGE:added new node address "{}"'.format(node_address))
            self.notify_listeners(NewNodeEvent(node_address))
        else:
            self._nodes[node_address.get_tech_type()][str(node_address.get_ip_address())].reset_lifetime()
            logging.debug('BRIDGE:refreshed node lifetime "{}"'.format(node_address))

    def remove_node_address_record(self, node_address: NodeAddress):
        if str(node_address.get_ip_address()) in self._nodes[node_address.get_tech_type()]:
            next_node_addresses = self._nodes[node_address.get_tech_type()][str(node_address.get_ip_address())].get_node_addresses()
            for next_node_address in next_node_addresses:
                next_node_address.remove_next_node_address(node_address)
            del self._nodes[node_address.get_tech_type()][str(node_address.get_ip_address())]

    def decrease_lifetime(self):
        for tech_type in self._types:
            for node_key in list(self._nodes[tech_type]):
                node = self._nodes[tech_type][node_key]
                node.decrease_lifetime()
                if node.get_lifetime() <= 0:
                    self.remove_node_address_record(node)

    def __str__(self):
        result = ""
        for tech_type in self._types:
            result += "tech {}: \n{}".format(tech_type, "\n".join(
                ["{}".format(value) for (key, value) in self._nodes[tech_type].items()]
            ))
        return result
