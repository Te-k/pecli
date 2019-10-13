class Plugin(object):
    name = "base"
    description = "base plugin"
    on_pe = True # Define if the command is always running on a PE file

    def add_arguments(self, parser):
        pass
