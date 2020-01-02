#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
from pecli.plugins.base import Plugin
from pecli.lib.richpe import get_richpe_hash, get_richpe_info


class PluginRichPE(Plugin):
    name = "richpe"
    description = "Decode Rich PE Header"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, pe, data):
        if pe.RICH_HEADER:
            info = get_richpe_info(pe)
            print("ProdId\tVersion\tCount\tProduct")
            for i in info:
                if i['product']:
                    print("{}\t{}\t{}\t{}".format(
                            i['prodid'],
                            i['version'],
                            i['count'],
                            i['product']
                        )
                    )
                else:
                    print("{}\t{}\t{}\t{}".format(
                            i['prodid'],
                            i['version'],
                            i['count']
                        )
                    )
            print("")
            print("RichPE Hash: {}".format(get_richpe_hash(pe)))
        else:
            print("No RichPE Header")
