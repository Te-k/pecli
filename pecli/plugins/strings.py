#! /usr/bin/env python
import pefile
import datetime
import os
import re
from pecli.plugins.base import Plugin

ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"



class PluginStrings(Plugin):
    name = "strings"
    description = "Extract strings from the PE file"
    on_pe = False

    def add_arguments(self, parser):
        parser.add_argument('--ascii', '-a', action="store_true", help="ASCII strings only")
        parser.add_argument('--wide', '-w', action="store_true", help="Wide strings only")
        parser.add_argument('-n', '--min-len', type=int, default=4,
                        help='Print sequences of characters that are at least ' +
                             'min-len characters long, instead of the default 4.')
        parser.add_argument('PEFILE', help='a PE file')
        self.parser = parser

    def run(self, args):
        # regular expressions from flare-floss:
        #  https://github.com/fireeye/flare-floss/blob/master/floss/strings.py#L7-L9
        re_narrow = re.compile(b'([%s]{%d,})' % (ASCII_BYTE, args.min_len))
        re_wide = re.compile(b'((?:[%s]\x00){%d,})' % (ASCII_BYTE, args.min_len))

        with open(args.PEFILE, 'rb') as f:
            data = f.read()

        if args.ascii:
            for match in re_narrow.finditer(data):
                print(match.group().decode('ascii'))
        if args.wide:
            for match in re_wide.finditer(data):
                try:
                    print(match.group().decode('utf-16'))
                except UnicodeDecodeError:
                    pass
        if not args.wide and not args.ascii:
            for match in re_narrow.finditer(data):
                print(match.group().decode('ascii'))
            for match in re_wide.finditer(data):
                try:
                    print(match.group().decode('utf-16'))
                except UnicodeDecodeError:
                    pass
