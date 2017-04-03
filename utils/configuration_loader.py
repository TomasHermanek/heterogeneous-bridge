import configparser


class ConfigurationLoader:
    def __init__(self, conf_parser: configparser):
        self.confParser = conf_parser

    """
    Function loads configuration
    """
    def read_configuration(self, config_file: str) -> dict:
        self.confParser.read(config_file)
        read_config = {
            "border-router": {},
            "serial": {},
            "metrics": {},
            "wifi": {}
        }
        for section in self.confParser.sections():
            if section == 'border-router':
                read_config[section]['ipv6'] = self.confParser[section]['ipv6']
            elif section == 'serial':
                read_config[section]['device'] = self.confParser[section]['device']
            elif section == 'wifi':
                read_config[section]['device'] = self.confParser[section]['device']
            elif section == 'metrics':
                read_config[section]['en'] = self.confParser[section]['en']
                read_config[section]['bw'] = self.confParser[section]['bw']
                read_config[section]['etx'] = self.confParser[section]['etx']
        return read_config
