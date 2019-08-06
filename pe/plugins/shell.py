#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
from pe.plugins.base import Plugin
from pe.lib.dotnet_guid import is_dot_net_assembly, get_guid
from IPython import embed


class PluginShell(Plugin):
    name = "shell"
    description = "Launch ipython shell to analyze the PE file"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, pe, data):
        embed()
