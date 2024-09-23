#! /usr/bin/env python
import os

import pkg_resources
import yara

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
        crypto_db = pkg_resources.resource_filename("pecli", "data/yara-crypto.yar")
        if not os.path.isfile(crypto_db):
            print("Problem accessing the yara database")
            return

        rules = yara.compile(filepath=crypto_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            for match in matches:
                paddr = match.strings[0].instances[0].offset
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
