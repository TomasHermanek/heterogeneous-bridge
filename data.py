from ipaddress import IPv6Address
import logging


class Data:
    def __init__(self, configuration):
        self._global_address = None
        self._link_local_address = None
        self._configuration = configuration

    def set_global_address(self, global_address):
        self._global_address = global_address

    def get_global_address(self):
        return self._global_address

    def set_link_local_address(self, link_local_address):
        self._link_local_address = link_local_address

    def get_link_local_address(self):
        return self._link_local_address

    def get_configuration(self):
        return self._configuration


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


class NodeTable:
    def __init__(self, types: list):
        self._nodes = {}
        self._types = types
        for tech_type in types:
            self._nodes.update({
                tech_type: {}
            })

    def node_exists(self, address: NodeAddress):
        pass

    def add_node_address(self, node_address: NodeAddress):
        if str(node_address.get_ip_address()) not in self._nodes[node_address.get_tech_type()]:
            self._nodes[node_address.get_tech_type()].update({
                str(node_address.get_ip_address()): node_address
            })
            logging.debug('BRIDGE:added new node address "{}"'.format(node_address))
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
            for node_key in self._nodes[tech_type]:
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
