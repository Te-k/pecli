#! /usr/bin/env python
import pefile
import datetime
import yara
import os
from pe.plugins.base import Plugin


class PluginCheck(Plugin):
    name = "check"
    description = "Check for weirdness in PE formate"
    # Known suspicious sections partially imported from
    # https://github.com/katjahahn/PortEx/blob/master/src/main/java/com/github/katjahahn/tools/anomalies/SectionTableScanning.scala
    know_suspicious_sections = {
	".arch":  "Alpha-architecture section",
	".bindat": "Binary data, e.g., by downware installers",
	".cormeta": "CLR Metadata section",
	".complua": "LUA compiler",
	".fasm": "Flat Assembler",
        ".flat" : "Flat Assembler",
	".idlsym": "IDL Attributes (registered SEH)",
	".impdata": "Alternative import section",
	".orpc": "Code section inside rpcrt4.dll",
	".rodata": "Read-only data section",
	".script": "Section containing script",
	".stab" : "GHC (Haskell)",
        ".stabstr" : "GHC (Haskell)",
	".sxdata" : "Registered Exception Handlers section",
	".xdata" : "Exception information section",
	"DGROUP" : "Legacy data group section",
	"BSS" : "Uninitialized Data section (Borland)",
	"CODE" : "Code section (Borland)",
	"DATA" : "Data section (Borland)",
	"INIT" : "INIT section of drivers",
        "PAGE" : "PAGE section of drivers",
	".aspack" : "Aspack packer",
        ".adata" : "Aspack/Armadillo packer",
	"ASPack" : "Aspack packer",
        ".ASPack" : "Aspack packer",
	".asspck" : "Aspack packer",
	".ccg" : "CCG Packer (Chinese)",
	"BitArts" : "Crunch 2.0 Packer",
	"DAStub" : "DAStub Dragon Armor protector",
	".charmve" : "Added by the PIN tool",
	".enigma1" : "Enigma Virtual Box protector",
	".enigma2" : "Enigma Virtual Box protector",
	"!EPack" : "EPack packer",
	".mackt" : "ImpRec-created section, this file was patched/cracked",
	".MaskPE" : "MaskPE Packer",
	"MEW" : "MEW packer",
	".MPRESS1" : "MPRESS Packer",
	".MPRESS2" : "MPRESS Packer",
        ".neolite" : "Neolite Packer", ".neolit" : "Neolite Packer",
        ".ndata" : "Nullsoft Installer",
        ".nsp0" : "NsPack packer",
        ".nsp1" : "NsPack packer",
        ".nsp2" : "NsPack packer",
        "nsp0" : "NsPack packer",
        "nsp0" : "NsPack packer",
        "nsp0" : "NsPack packer",
        ".packed" : "RLPack Packer", #  first section only
        "pebundle" : "PEBundle Packer",
        "PEBundle" : "PEBundle Packer",
        "PEC2TO" : "PECompact packer","PEC2" : "PECompact packer",
        "pec1" : "PECompact packer","pec2" : "PECompact packer",
        "PEC2MO" : "PECompact packer", "PEC2TO" : "PECompact packer",
        "PECompact2" : "PECompact packer",
        "PELOCKnt" : "PELock Protector",
        ".perplex" : "Perplex PE-Protector",
        "PESHiELD" : "PEShield Packer",
        ".petite" : "Petite Packer",
        ".pinclie" : "Added by the PIN tool",
        "ProCrypt" : "ProCrypt Packer",
        ".RLPack" : "RLPack Packer", # second section
        ".rmnet" : "Ramnit virus marker",
        "RCryptor" : "RPCrypt Packer", ".RPCrypt" : "RPCrypt Packer",
        ".sforce3" : "StarForce Protection",
        ".spack" : "Simple Pack (by bagie)",
        ".svkp" : "SVKP packer",
        ".Themida" : "Themida","Themida" : "Themida",
        ".tsuarch" : "TSULoader", ".tsustub" : "TSULoader",
        "PEPACK!!" : "Pepack",
        ".Upack" : "Upack packer",
        ".ByDwing" : "Upack packer",
        "UPX0" : "UPX packer", "UPX1" : "UPX packer", "UPX2" : "UPX packer",
        "UPX!" : "UPX packer", ".UPX0" : "UPX packer", ".UPX1" : "UPX packer",
        ".UPX2" : "UPX packer",
        ".vmp0" : "VMProtect packer",".vmp1" : "VMProtect packer",".vmp2" : "VMProtect packer",
        "VProtect" : "Vprotect Packer",
        "WinLicen" : "WinLicense (Themida) Protector",
        ".WWPACK" : "WWPACK Packer",
        ".yP" : "Y0da Protector", ".y0da" : "Y0da Protector"
    }
    normal_sections = [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    imphashes = {
        "25c0914e1e7dc7c3bb957d88e787a155": "Enigma VirtualBox"
    }

    def normal_section_name(self, section_name):
        if isinstance(section_name, bytes):
            n = section_name.decode('utf-8').strip('\x00')
        else:
            n = section_name.strip('\x00')
        return n in self.normal_sections

    def check_abnormal_section_name(self, pe):
        res = [x.Name.decode('utf-8').strip('\x00') for x in pe.sections if not self.normal_section_name(x.Name)]
        if len(res) > 0:
            print("[+] Abnormal section names: %s" % " ".join(res))

    def check_known_suspicious_sections(self, pe):
        names = [x.Name.decode('utf-8').strip('\x00') for x in pe.sections]
        res = list(filter(lambda x: x in self.know_suspicious_sections.keys(), names))
        if len(res) > 0:
            print("[+] Known malicious sections")
            for r in res:
                print("\t-%s: %s" % (r, self.know_suspicious_sections[r]))

    def check_imphash(self, pe):
        """Check imphash in a list of known import hashes"""
        ih = pe.get_imphash()
        if ih in self.imphashes:
            print("[+] Known suspicious import hash: %s" % (self.imphashes[ih]))

    def check_pe_size(self, pe, data):
        """Check for extra data in the PE file by comparing PE info and data size"""
        length = max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))
        if length < len(data):
            print("[+] %i extra bytes in the file" % (len(data) - length))

    def check_pe_sections(self, pe):
        """Search for PE headers at the beginning of sections"""
        res = []
        for section in pe.sections:
            if b"!This program cannot be run in DOS mode" in section.get_data()[:400] or\
                    b"This program must be run under Win32" in section.get_data()[:400]:
                res.append(section.Name.decode('utf-8').strip('\x00'))

        if len(res) > 0:
            print("[+] PE header in sections %s" % " ".join(res))

    def check_tls(self, pe):
        """Check if there is a TLS callback"""
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
        if len(callbacks) > 0:
            if len(callbacks) == 1:
                print("[+] TLS Callback: 0x%x" % callbacks[0])
            else:
                print("[+] TLS Callbacks:")
                for r in callbacks:
                    print("\t- 0x%s" % r)

    def check_peid(self, data):
        """Check on PEid signatures"""
        peid_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/PeID.yara"
        rules = yara.compile(filepath=peid_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            print("[+} PeID packer: %s" % ", ".join(matches))

    def run(self, pe, args):
        with open(args.PEFILE, 'rb') as f:
            data = f.read()
        print("Running checks on %s:" % args.PEFILE)
        self.check_abnormal_section_name(pe)
        self.check_known_suspicious_sections(pe)
        self.check_pe_size(pe, data)
        self.check_tls(pe)
        self.check_pe_sections(pe)
        self.check_peid(data)
        self.check_imphash(pe)
