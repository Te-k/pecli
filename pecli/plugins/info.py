#! /usr/bin/env python
import sys
import json
import hashlib
import pefile
import datetime
import magic
import copy
from pecli.plugins.base import Plugin
from pecli.lib.display import display_sections
from pecli.lib.dotnet_guid import get_guid, is_dot_net_assembly
from pecli.lib.utils import debug_filename, debug_guid
from pecli.lib.richpe import get_richpe_hash


class PluginInfo(Plugin):
    name = "info"
    description = "Extract info from the PE file"

    def is_signed(self, pe):
        """
        Check if the PE is signed
        Return True / False
        """
        return (pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress != 0)

    def search_section(self, pe, address, physical=True):
        """Search the section of the given address (return None if not found)"""
        if physical:
            for s in pe.sections:
                if (address >= s.PointerToRawData) and (address <= s.PointerToRawData + s.SizeOfRawData):
                    #vaddr = pe.OPTIONAL_HEADER.ImageBase + pos - s.PointerToRawData + s.VirtualAddress
                    return s.Name.decode('utf-8', 'ignore').strip('\x00')
        else:
            for s in pe.sections:
                if (address >= (pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress)) and (address <= (pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress + s.Misc_VirtualSize)):
                    return s.Name.decode('utf-8', 'ignore').strip('\x00')

        return None

    def check_tls(self, pe):
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0:
                    break
                callbacks.append(func)
                idx += 1
        return callbacks

    def display_hashes(self, data, pe):
        """Display md5, sha1 and sh256 of the data given"""
        for algo in ["md5", "sha1", "sha256"]:
            m = getattr(hashlib, algo)()
            m.update(data)
            print("%-15s %s" % (algo.upper()+":", m.hexdigest()))
        print("%-15s %s" % ("Imphash:", pe.get_imphash()))

    def display_headers(seld, pe):
        """Display header information"""
        if pe.FILE_HEADER.IMAGE_FILE_DLL:
            print("DLL File! ")
        print("Compile Time:\t%s (UTC - 0x%-8X)"  %(str(datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)), pe.FILE_HEADER.TimeDateStamp))

    def display_imports(self, pe):
        """Display imports"""
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(entry.dll.decode('utf-8'))
                for imp in entry.imports:
                    if imp.name:
                        print('\t%s %s' % (hex(imp.address), imp.name.decode('utf-8')))
                    else:
                        print('\t%s %s' % (hex(imp.address), str(imp.ordinal)))


    def display_exports(self, pe):
        """Display exports"""
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print("%s %s %s" % (
                    hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                    exp.name.decode('utf-8', 'ignore'),
                    exp.ordinal
                ))
        except AttributeError:
            return

    def display_debug(self, pe):
        """Display debug infos"""
        debug_fn = debug_filename(pe)
        debug_g = debug_guid(pe)
        if debug_fn:
            print("Debug Filename:\t{}".format(debug_fn))
        if debug_g:
            print("Debug GUID:\t{}".format(debug_g))

    def resource(self, pe, level, r, parents):
        """Recursive printing of resources"""
        if hasattr(r, "data"):
            # resource
            offset = r.data.struct.OffsetToData
            size = r.data.struct.Size
            data = pe.get_memory_mapped_image()[offset:offset+size]
            m = hashlib.md5()
            m.update(data)
            print("%-12s %-7s %-9s %-14s %-17s %-14s %-9s" % (
                    "-".join(parents + [str(r.id)]),
                    str(r.name),
                    "%i B" % size,
                    pefile.LANG.get(r.data.lang, 'UNKNOWN'),
                    pefile.get_sublang_name_for_lang(r.data.lang, r.data.sublang),
                    magic.from_buffer(data),
                    m.hexdigest()
                )
            )
        else:
            # directory
            parents = copy.copy(parents)
            if r.id is not None:
                parents.append(str(r.id))
            else:
                parents.append(r.name.string.decode('utf-8'))
            for r2 in r.directory.entries:
                self.resource(pe, level+1, r2, parents)

    def display_resources(self, pe):
        """Display resources"""
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            if(len(pe.DIRECTORY_ENTRY_RESOURCE.entries) > 0):
                print("Resources:")
                print("=" * 80)
                print("%-12s %-7s %-9s %-14s %-17s %-14s %-9s" % ("Id", "Name", "Size", "Lang", "Sublang", "Type", "MD5"))
                for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    self.resource(pe, 0, r, [])

    def add_arguments(self, parser):
        parser.add_argument('--sections', '-s', action='store_true', help='Only display sections')
        parser.add_argument('--imports', '-i',  action='store_true', help='Display imports only')
        parser.add_argument('--exports', '-e',  action='store_true', help='Display exports only')
        parser.add_argument('--resources', '-r',  action='store_true', help='Display resources only')
        parser.add_argument('--full', '-f',  action='store_true', help='Full dump of all pefile infos')
        self.parser = parser

    def run(self, args, pe, data):
        if args.sections:
            display_sections(pe)
            sys.exit(0)
        if args.imports:
            self.display_imports(pe)
            sys.exit(0)
        if args.exports:
            self.display_exports(pe)
            sys.exit(0)
        if args.resources:
            self.display_resources(pe)
            sys.exit(0)
        if args.full:
            print(pe.dump_info())
            sys.exit(0)

        # Metadata
        print("Metadata")
        print("=" * 80)
        self.display_hashes(data, pe)
        print("Size:\t\t%d bytes" % len(data))
        print("Type:\t\t%s" % magic.from_buffer(data))
        self.display_headers(pe)
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        section = self.search_section(pe, entry_point, physical=False)
        print("Entry point:\t0x%x (section %s)" % (pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase, section))
        res = self.check_tls(pe)
        if len(res) > 0:
            if len(res) == 1:
                section = self.search_section(pe, res[0], physical=False)
                print("TLS Callback:\t0x%x (section %s)" % (res[0], section))
            else:
                print("TLS Callback:")
                for r in res:
                    section = self.search_section(pe, r, physical=False)
                    print("\t\t0x%x (section %s)" % (r, section))
        if is_dot_net_assembly(pe):
            try:
                res = get_guid(pe, data)
                print(".NET MVid\t{}".format(res["mvid"]))
                print(".NET TypeLib\t{}".format(res['typelib_id']))
            except:
                print("Impossible to parse .NET GUID")

        self.display_debug(pe)
        richpe = get_richpe_hash(pe)
        if richpe:
            print("RichPE Hash\t{}".format(richpe))
        if self.is_signed(pe):
            print("Signed PE file")

        # Sections
        print("")
        print("Sections")
        print("=" * 80)
        display_sections(pe)
        print("")
        print("Imports")
        print("=" * 80)
        self.display_imports(pe)
        print("")
        self.display_exports(pe)
        print("")
        self.display_resources(pe)
