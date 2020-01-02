#! /usr/bin/env python
import pefile
import datetime
import yara
import os
import copy
from pecli.plugins.base import Plugin


class PluginSig(Plugin):
    name = "sig"
    description = "Handle PE Signature"
    on_pe = False

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('info', help='Extract information on the signature')
        parser_a.add_argument('PEFILE', help='a PE file')
        parser_a.set_defaults(subcommand='info')
        parser_b = subparsers.add_parser('extract', help='Extract the siganture of a PE file')
        parser_b.add_argument('PEFILE', help='a PE file')
        parser_b.add_argument('--output', '-o', help='Output file')
        parser_b.set_defaults(subcommand='extract')
        self.parser = parser

    def run(self, args):
        if hasattr(args, 'subcommand'):
            if args.subcommand == 'info':
                pe =  pefile.PE(args.PEFILE)
                address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
                if address == 0:
                    print("This PE file is not signed")
                else:
                    print("This PE file is signed")
                    # TODO : implement parsing of the signature
            elif args.subcommand == 'extract':
                if args.output:
                    output = args.output
                else:
                    output = args.PEFILE + '.sig'
                pe =  pefile.PE(args.PEFILE)

                address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
                size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
                if address == 0:
                    print('This PE file is not signed')
                else:
                    signature = pe.write()[address+8:]
                    f = open(output, 'wb+')
                    f.write(signature)
                    f.close()
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
