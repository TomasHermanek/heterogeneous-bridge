import logging
from ipaddress import IPv6Address
from interface_listener import PacketSender, MoteNeighbourSolicitationEvent, NeighbourAdvertisementEvent
from threading import Thread
from event_system import EventListener, Event, EventProducer
from data import Data
import time
import math


class NodeAddress:
    DEFAULT_LIFETIME = 255

    def __init__(self, ip_address: IPv6Address, tech_type):
        self._ip_address = ip_address
        self._lifetime = self.DEFAULT_LIFETIME
        self._type = tech_type
        self._next_address = {}

    def get_ip_address(self) -> IPv6Address:
        return self._ip_address

    def has_neighbor_with_tech(self, tech_type: str):
        for key in self._next_address:
            if self._next_address[key].get_tech_type() == tech_type:
                return True
        return False

    def get_tech_type(self) -> str:
        return self._type

    def get_lifetime(self) -> int:
        return self._lifetime

    def reset_lifetime(self):
        self._lifetime = self.DEFAULT_LIFETIME

    def decrease_lifetime(self):
        self._lifetime -= 1
        return self._lifetime

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
        return "{:<30}{:<10}[{}]".format(str(self._ip_address), self._lifetime, "".join(
            ["{}({});".format(str(value.get_ip_address()), value.get_tech_type()) for (key, value) in self._next_address.items()]
        ))


class NewNodeEvent(Event):
    def __init__(self, data: NodeAddress):
        Event.__init__(self, data)

    def __str__(self):
        return "new-node-event"


class NodeRefreshEvent(Event):
    def __init__(self, data: NodeAddress):
        Event.__init__(self, data)

    def __str__(self):
        return "node-refresh-event"


class NodeTable(EventProducer):
    WIFI_NODE_REFRESH_INTERVAL = math.floor(NodeAddress.DEFAULT_LIFETIME / 2)

    def __init__(self, types: list):
        EventProducer.__init__(self)
        self.add_event_support(NewNodeEvent)
        self.add_event_support(NodeRefreshEvent)
        self._nodes = {}
        self._types = types
        for tech_type in types:
            self._nodes.update({
                tech_type: {}
            })

    def has_node(self, address: str):
        for node_type in self._types:
            if address in self._nodes[node_type]:
                return True
        return False

    def get_node_address(self, address: str, type: str):
        if address in self._nodes[type]:
            return self._nodes[type][address]
        return None

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
            for key in list(next_node_addresses):
                next_node_addresses[key].remove_next_node_address(node_address)
            del self._nodes[node_address.get_tech_type()][str(node_address.get_ip_address())]

    def decrease_lifetime(self):
        for tech_type in self._types:
            for node_key in list(self._nodes[tech_type]):
                node = self._nodes[tech_type][node_key]
                node.decrease_lifetime()
                if tech_type == "wifi" and node.get_lifetime() == self.WIFI_NODE_REFRESH_INTERVAL:
                    self.notify_listeners(NodeRefreshEvent(node))
                if node.get_lifetime() <= 0:
                    self.remove_node_address_record(node)

    def __str__(self):
        result = "Node Table\n{:<30}{:<10}[{}]\n".format("Dst IP", "Lifetime", "next Ip address(technology);")
        for tech_type in self._types:
            result += "Technology {}: \n{}\n".format(tech_type, "\n".join(
                ["{}".format(value) for (key, value) in self._nodes[tech_type].items()]
            ))
        return result

    def print_table(self):
        print(str(self))


class PendingEntry(Thread):
    MAX_ATTEMPTS = 4
    ATTEMPT_DELAY_MULTIPLICATION = 5
    STATUS_PENDING = 1
    STATUS_SUCCESS = 2
    STATUS_FAILED = 3

    def __init__(self, address: str, sender_function):
        Thread.__init__(self)
        self._address = address
        self._sender_function = sender_function
        self._attempt = 0
        self._status = self.STATUS_PENDING

    def inc_attempt(self):
        self._attempt += 1

    def get_attempt(self):
        return self._attempt

    def set_status(self, status: int):
        if status in [self.STATUS_FAILED, self.STATUS_SUCCESS, self.STATUS_PENDING]:
            self._status = status

    def run(self):
        while self._status == self.STATUS_PENDING and self._attempt <= PendingEntry.MAX_ATTEMPTS:
            self._sender_function(self._address)
            self.inc_attempt()
            time.sleep(self._attempt * PendingEntry.ATTEMPT_DELAY_MULTIPLICATION)
        if self._status == self.STATUS_PENDING:
            self._status = PendingEntry.STATUS_FAILED

    def finish(self):
        self._attempt = PendingEntry.MAX_ATTEMPTS + 1

    def __str__(self):
        return "{:<30}{:5}{:15}".format(self._address, self._attempt, self._status)


class PendingSolicitations:
    def __init__(self):
        self._pendings = {}

    def add_pending(self, address: str, sender_function):
        if address not in self._pendings:
            pending = PendingEntry(address, sender_function)
            self._pendings.update({address: pending})
            pending.start()

    def remove_pending(self, address: str):
        if address in self._pendings:
            self._pendings[address].finish()
            del self._pendings[address]

    def get_pending(self, address: str):
        if address in self._pendings:
            return self._pendings[address]

    def has_pending(self, address: str):
        return address in self._pendings

    def inc_pending(self, address: str):
        if address in self._pendings:
            self._pendings[address].inc_attempt()

    def __str__(self):
        header = "{:<30}{:10}{:15}\n".format("Ip address", "Attempt", "Status({}-pending/{}-success/{}-failed)".format(
            PendingEntry.STATUS_PENDING, PendingEntry.STATUS_SUCCESS, PendingEntry.STATUS_FAILED
        ))
        return header + "".join(["{}\n".format(value) for (key, value) in self._pendings.items()])

    def print_pendings(self):
        print(self)


class NeighborManager(EventListener):
    def __init__(self, node_table: NodeTable, data: Data, pendings: PendingSolicitations, packet_sender: PacketSender,
                 slip_commands):
        EventListener.__init__(self)
        self._pendings = pendings
        self._sender = packet_sender
        self._data = data
        self._node_table = node_table
        self._slip_commands = slip_commands

    def notify(self, event: Event):
        from serial_connection import RequestRouteToMoteEvent
        if isinstance(event, MoteNeighbourSolicitationEvent):
            self._sender.send_icmpv6_na(src_ip=event.get_event()["src_ip"], target_ip=event.get_event()["target_ip"])

        elif isinstance(event, NewNodeEvent):
            technology = event.get_event().get_tech_type()
            if technology != "wifi":
                new_ip = str(event.get_event().get_ip_address())
                self._pendings.add_pending(new_ip, self._sender.send_icmpv6_ns)
        elif isinstance(event, NodeRefreshEvent):
            technology = event.get_event().get_tech_type()
            if technology == "wifi":
                mote_ip = None
                next_node = event.get_event().get_node_addresses()
                for key in next_node:
                    if next_node[key].get_tech_type() == "rpl":
                        mote_ip = str(next_node[key].get_ip_address())
                if mote_ip:
                    self._pendings.remove_pending(mote_ip)
                    self._pendings.add_pending(mote_ip, self._sender.send_icmpv6_ns)
        elif isinstance(event, NeighbourAdvertisementEvent):
            src_ip = event.get_event()["src_ip"]
            target_ip = event.get_event()["target_ip"]
            if self._pendings.has_pending(target_ip):
                pending = self._pendings.get_pending(target_ip)
                if pending:
                    pending.set_status(PendingEntry.STATUS_SUCCESS)
                # self._pendings.remove_pending(target_ip)

                wifi_node_address = self._node_table.get_node_address(src_ip, 'wifi')
                if not wifi_node_address:
                    wifi_node_address = NodeAddress(src_ip, 'wifi')
                self._node_table.add_node_address(wifi_node_address)

                mote_node_address = self._node_table.get_node_address(target_ip, 'rpl')
                if mote_node_address:
                    mote_node_address.add_next_node_address(wifi_node_address)
        elif isinstance(event, RequestRouteToMoteEvent):
            node = self._node_table.get_node_address(event.get_event()["ip_addr"], 'rpl')
            if node and node.has_neighbor_with_tech('wifi'):
                response = 1
            else:
                response = 0
            self._slip_commands.send_route_request_response_to_contiki(event.get_event()["question_id"], response)

    def __str__(self):
        return 'neighbor-manager'
