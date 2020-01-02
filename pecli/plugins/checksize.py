#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
from pecli.plugins.base import Plugin
from pecli.lib.display import display_sections

class PluginSize(Plugin):
    name = "checksize"
    description = "Check size of the PE file"

    def get_pe_size(self, pe, verbose=True):
        """Return the PE size obtained from the file itself"""
        return max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))

    def add_arguments(self, parser):
        parser.add_argument('--quiet', '-q', action='store_true', help='Quiet output')
        parser.add_argument('--extra', '-e',  help='Dump extra data in another file')
        parser.add_argument('--write', '-w',  help='Copy the file with the right size')
        self.parser = parser

    def run(self, args, pe, data):
        if not args.quiet:
            display_sections(pe)

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
