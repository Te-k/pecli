#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
from pe.plugins.base import Plugin

class PluginSize(Plugin):
    name = "checksize"
    description = "Check size of the PE file"

    def get_pe_size(self, pe, verbose=True):
        """Return the PE size obtained from the file itself"""
        return max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))

    def display_sections(self, pe):
        """Display information about the PE sections"""
        print("Name\t\tVirtualSize\tVirtualAddress\tRawSize\t\tRawAddress")
        for section in pe.sections:
            name = section.Name.decode('utf-8').strip('\x00')
            if len(name) < 8:
                print("%s\t\t%s\t\t%s\t\t%s\t\t%s" % (
                    name,
                    hex(section.Misc_VirtualSize),
                    hex(section.VirtualAddress),
                    hex(section.PointerToRawData),
                    hex(section.SizeOfRawData)
                ))
            else:
                print("%s\t%s\t\t%s\t\t%s\t\t%s" % (
                    name,
                    hex(section.Misc_VirtualSize),
                    hex(section.VirtualAddress),
                    hex(section.PointerToRawData),
                    hex(section.SizeOfRawData)
                ))
        print("")


    def add_arguments(self, parser):
        parser.add_argument('--quiet', '-q', action='store_true', help='Quiet output')
        parser.add_argument('--extra', '-e',  help='Dump extra data in another file')
        parser.add_argument('--write', '-w',  help='Copy the file with the right size')
        self.parser = parser

    def run(self, pe, args):
        with open(args.PEFILE, 'rb') as f:
            data = f.read()

        if not args.quiet:
            self.display_sections(pe)

        size = self.get_pe_size(pe)
        if len(data) > size:
            print("%i bytes of extra data (%i while it should be %i)" % (
                len(data) - size,
                len(data),
                size
            ))
            if args.write is not None:
                fout = open(args.write, 'wb')
                fout.write(data[:size])
                fout.close()
                print('Correct PE dumped in %s' % args.write)
            if args.extra is not None:
                fout = open(args.extra, 'wb')
                fout.write(data[size:])
                fout.close()
                print('Dumped extra data in %s' % args.extra)
        else:
            if len(data) == size:
                print('Correct size')
            else:
                print("File too short (%i while it should be %i)" % (len(data), size))

            if args.write is not None or args.extra is not None:
                print('No extradata, can\'t do anything for you, sorry!')
