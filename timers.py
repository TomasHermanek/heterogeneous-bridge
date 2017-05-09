from threading import Thread
from serial_connection import SerialCommands
from neighbors import NodeTable
import time


class NeighbourRequestTimer(Thread):
    """
    Timer for sending request periodically over serial line
    """
    def __init__(self, request_time: int, slip_commands: SerialCommands):
        Thread.__init__(self)
        self._neighbours_request_time = request_time
        self._slip_commands = slip_commands

    def run(self):
        time.sleep(5)
        while 1:
            self._slip_commands.request_neighbours_from_contiki()
            time.sleep(self._neighbours_request_time)


class PurgeTimer(Thread):
    """
    Timer responsible for decreasing lifetime of records
    """
    def __init__(self, purging_interval: int, node_table: NodeTable):
        Thread.__init__(self)
        self._purging_interval = purging_interval
        self._node_table = node_table

    def run(self):
        while 1:
            self._node_table.decrease_lifetime()
            time.sleep(self._purging_interval)
