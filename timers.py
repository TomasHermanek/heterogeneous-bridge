from threading import Thread
from serial_connection import SlipCommands
from neighbors import NodeTable
import time


class NeighbourRequestTimer(Thread):
    def __init__(self, request_time: int, slip_commands: SlipCommands):
        Thread.__init__(self)
        self._neighbours_request_time = request_time
        self._slip_commands = slip_commands

    def run(self):
        time.sleep(5)
        while 1:
            self._slip_commands.request_neighbours_from_contiki()
            time.sleep(self._neighbours_request_time)


class PurgeTimer(Thread):
    def __init__(self, purging_interval: int, node_table: NodeTable):
        Thread.__init__(self)
        self._purging_interval = purging_interval
        self._node_table = node_table

    def run(self):
        while 1:
            self._node_table.decrease_lifetime()
            # print(self._node_table)
            time.sleep(self._purging_interval)
