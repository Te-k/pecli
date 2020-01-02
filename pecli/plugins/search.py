#! /usr/bin/env python
import sys
import pefile
from pecli.plugins.base import Plugin

class PluginSearch(Plugin):
    name = "search"
    description = "Search for a string in a PE file"

    def add_arguments(self, parser):
        parser.add_argument('STRING', help='a string')
        self.parser = parser

    def run(self, args, pe, data):
        pos = data.find(args.STRING.encode('utf-8'))
        if pos == -1:
            print("String not found...")
            sys.exit(1)

        print('Position in the file : 0x%x' % pos)

        # Search position in the PE
        # Check in sections first
        for s in pe.sections:
            if (pos >= s.PointerToRawData) and (pos <= s.PointerToRawData + s.SizeOfRawData):
                vaddr = pe.OPTIONAL_HEADER.ImageBase + pos - s.PointerToRawData + s.VirtualAddress
                print("In section %s at address 0x%x" % (s.Name.decode('utf-8', 'ignore'), vaddr))
