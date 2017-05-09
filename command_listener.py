from threading import Thread


class Command:
    """
    Defines single commands which is used by command line
    """
    def __init__(self, command_string: str, class_method, help_text: str):
        self._command_string = command_string
        self._class_method = class_method
        self.help_text = help_text

    def get_command_string(self)->str:
        return self._command_string

    def get_help_text(self)->str:
        return self.help_text

    def execute_command(self):
        self._class_method()


class CommandListener(Thread):
    """
    Thread which listens for commands on command line
    """
    def __init__(self):
        Thread.__init__(self)
        self.commands = {}
        self.add_command(Command("help", self.print_help, "Shows help"))

    def print_help(self):
        print("{:<20}{}".format("Command", "Command description"))
        for key, command in self.commands.items():
            print("{:<20}{}".format(key, command.get_help_text()))

    def add_command(self, command: Command):
        self.commands.update({command.get_command_string(): command})

    def run(self):
        while True:
            cmd = input(">> ")
            if cmd in self.commands:
                self.commands[cmd].execute_command()
