import os
import sys
import argparse
import pefile
from pecli.plugins.base import Plugin

def init_plugins():
    plugin_dir = os.path.dirname(os.path.realpath(__file__)) + '/plugins'
    plugin_files = [x[:-3] for x in os.listdir(plugin_dir) if x.endswith(".py")]
    sys.path.insert(0, plugin_dir)
    for plugin in plugin_files:
        mod = __import__(plugin)

    PLUGINS = {}
    for plugin in Plugin.__subclasses__():
        PLUGINS[plugin.name] = plugin()
    return PLUGINS


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='Plugins')

    # Init plugins
    plugins = init_plugins()
    for p in plugins:
        sp = subparsers.add_parser(
            plugins[p].name,
            help=plugins[p].description
        )
        plugins[p].add_arguments(sp)
        if plugins[p].on_pe:
            sp.add_argument('PEFILE', help='a PE file')
        sp.set_defaults(plugin=p)

    args = parser.parse_args()
    if hasattr(args, 'plugin'):
        if plugins[args.plugin].on_pe:
            try:
                with open(args.PEFILE, 'rb') as f:
                    data = f.read()
                pe = pefile.PE(data=data)
                plugins[args.plugin].run(args, pe, data)
            except pefile.PEFormatError:
                print("Invalid PE file")
            except FileNotFoundError:
                print("File not found")
        else:
            plugins[args.plugin].run(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
