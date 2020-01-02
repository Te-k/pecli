#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
from pecli.plugins.base import Plugin


class PluginDump(Plugin):
    name = "dump"
    description = "Dump resource or section of the file"

    def add_arguments(self, parser):
        parser.add_argument('--section', '-s', help='Dump the section with the given name')
        parser.add_argument('--resource', '-r', help='Dump the given resource (live 12/10/133)')
        parser.add_argument('--output', '-o', help='Name of the output file')
        parser.add_argument('--debug', '-d', action='store_true', help='Show debug info')
        # TODO: feature to dump everything
        self.parser = parser

    def resource(self, pe, level, r, target, debug):
        """Recursive printing of resources"""
        if hasattr(r, "data"):
            if target[level] == str(r.name) or target[level] == str(r.id):
                if debug:
                    print("  " * level + "Found resource " + str(r.id))
                # Found
                offset = r.data.struct.OffsetToData
                size = r.data.struct.Size
                data = pe.get_memory_mapped_image()[offset:offset+size]
                return data
        else:
            # directory
            if target[level] == str(r.name) or target[level] == str(r.id):
                if debug:
                    print("  "*level + "Exploring directory " + str(r.id))
                for r2 in r.directory.entries:
                    res = self.resource(pe, level+1, r2, target, debug)
                    if res:
                        return res
            else:
                print("  "*level + "Directory " + str(r.id) + " not explored")

    def run(self, args, pe, data):
        if args.section:
            for s in pe.sections:
                if args.section in s.Name.decode('utf-8'):
                    if args.output is None:
                        output = s.Name.decode('utf-8').strip('\x00')[1:]
                    else:
                        output = args.output
                    with open(output, 'wb+') as f:
                        f.write(s.get_data())
                    print("Section %s written in %s" % (s.Name.decode('utf-8').strip('\x00'), output))
                    sys.exit(0)
            print("Section not found")
        elif args.resource:
            level = 0
            search = args.resource.split("/")
            found = False
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    data = self.resource(pe, 0, r, search, args.debug)
                    if data is not None:
                        found = True
                        if args.output is None:
                            output = args.resource.replace("/", "_")
                        else:
                            output = args.output
                        with open(output, 'wb+') as f:
                            f.write(data)
                        print("data found, size %i" % len(data))
                        print("Resource written in %s" % (output))
            if not found:
                print("This resource was not found")
        else:
            self.parser.print_help()
