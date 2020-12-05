#! /usr/bin/env python
import pefile
import datetime
import yara
import os
import copy
from pecli.plugins.base import Plugin


class PluginCrypto(Plugin):
    name = "crypto"
    description = "Identifies cryptographic values"

    def add_arguments(self, parser):
        self.parser = parser

    def convert_physical_addr(self, pe, addr):
        """
        Convert a physical address into its logical address
        """
        for s in pe.sections:
            if (addr >= s.PointerToRawData) and (addr <= s.PointerToRawData + s.SizeOfRawData):
                vaddr = pe.OPTIONAL_HEADER.ImageBase + addr - s.PointerToRawData + s.VirtualAddress
                return (s.Name.decode('utf-8', 'ignore').strip('\x00'), vaddr)
        return (None, None)


    def run(self, args, pe, data):
        crypto_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/yara-crypto.yar"
        if not os.path.isfile(crypto_db):
            print("Problem accessing the yara database")
            return

        rules = yara.compile(filepath=crypto_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            for match in matches:
                paddr = match.strings[0][0]
                section, vaddr = self.convert_physical_addr(pe, paddr)
                if section:
                    print("Found : {} at {} ({} - {})".format(
                        match.rule,
                        hex(paddr),
                        section,
                        hex(vaddr)
                    ))
                else:
                    print("Found : {} at {} (Virtual Address and section not found)".format(match.rule, hex(paddr)))
        else:
            print("No cryptographic data found!")
