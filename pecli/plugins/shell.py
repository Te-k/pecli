#! /usr/bin/env python
from IPython import embed

from pecli.plugins.base import Plugin


class PluginShell(Plugin):
    name = "shell"
    description = "Launch ipython shell to analyze the PE file"

    def add_arguments(self, parser):
        self.parser = parser

    def run(self, args, pe, data):
        embed()
