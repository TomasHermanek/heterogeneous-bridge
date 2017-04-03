

class Data:
    def __init__(self):
        self._src_ip = None

    def set_src_ip(self, src_ip):
        self._src_ip = src_ip

    def get_src_ip(self):
        return self._src_ip
