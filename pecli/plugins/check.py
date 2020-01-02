#! /usr/bin/env python
import pefile
import datetime
import yara
import os
import copy
from pecli.plugins.base import Plugin


class PluginCheck(Plugin):
    name = "check"
    description = "Check for stuff in the file"
    # Known suspicious sections partially imported from
    # https://github.com/katjahahn/PortEx/blob/master/src/main/java/com/github/katjahahn/tools/anomalies/SectionTableScanning.scala
    # http://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
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
        ".boom": "The Boomerang List Builder",
	".ccg" : "CCG Packer (Chinese)",
	"BitArts" : "Crunch 2.0 Packer",
	"DAStub" : "DAStub Dragon Armor protector",
	".charmve" : "Added by the PIN tool",
        ".ecode": "Developed with  Easy Programming Language (EPL)",
        ".edata": "Developed with  Easy Programming Language (EPL)",
	".enigma1" : "Enigma Virtual Box protector",
	".enigma2" : "Enigma Virtual Box protector",
	"!EPack" : "EPack packer",
        ".gentee": "Gentee installer",
        ".kkrunchy": "kkrunchy Packer",
        "lz32.dll": "Crinkler",
	".mackt" : "ImpRec-created section, this file was patched/cracked",
	".MaskPE" : "MaskPE Packer",
	"MEW" : "MEW packer",
	".MPRESS1" : "MPRESS Packer",
	".MPRESS2" : "MPRESS Packer",
        ".neolite" : "Neolite Packer",
        ".neolit" : "Neolite Packer",
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
        "PEC2TO" : "PECompact packer",
        "PEC2" : "PECompact packer",
        "pec1" : "PECompact packer",
        "pec2" : "PECompact packer",
        "PEC2MO" : "PECompact packer",
        "PEC2TO" : "PECompact packer",
        "PECompact2" : "PECompact packer",
        "PELOCKnt" : "PELock Protector",
        ".perplex" : "Perplex PE-Protector",
        "PESHiELD" : "PEShield Packer",
        ".petite" : "Petite Packer",
        ".pinclie" : "Added by the PIN tool",
        "ProCrypt" : "ProCrypt Packer",
        ".RLPack" : "RLPack Packer", # second section
        ".rmnet" : "Ramnit virus marker",
        "RCryptor" : "RPCrypt Packer",
        ".RPCrypt" : "RPCrypt Packer",
        ".seau": "SeauSFX Packer",
        ".sforce3" : "StarForce Protection",
        ".spack" : "Simple Pack (by bagie)",
        ".svkp" : "SVKP packer",
        ".Themida" : "Themida",
        "Themida" : "Themida",
        ".tsuarch" : "TSULoader",
        ".tsustub" : "TSULoader",
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
        ".yP" : "Y0da Protector",
        ".y0da" : "Y0da Protector",
    }
    normal_sections = [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    imphashes = {
        "25c0914e1e7dc7c3bb957d88e787a155": "Enigma VirtualBox"
    }
    resource_names = {
        "PYTHONSCRIPT": "PY2EXE binary",
        "PYTHON27.DLL": "PY2EXE binary"
    }

    def normal_section_name(self, section_name):
        if isinstance(section_name, bytes):
            n = section_name.decode('utf-8', 'ignore').strip('\x00')
        else:
            n = section_name.strip('\x00')
        return n in self.normal_sections

    def check_abnormal_section_name(self, pe):
        res = [x.Name.decode('utf-8', 'ignore').strip('\x00') for x in pe.sections if not self.normal_section_name(x.Name)]
        if len(res) > 0:
            print("[+] Abnormal section names: %s" % " ".join(res))
            return True
        else:
            return False

    def check_known_suspicious_sections(self, pe):
        names = [x.Name.decode('utf-8', 'ignore').strip('\x00') for x in pe.sections]
        res = list(filter(lambda x: x in self.know_suspicious_sections.keys(), names))
        if len(res) > 0:
            print("[+] Known malicious sections")
            for r in res:
                print("\t-%s: %s" % (r, self.know_suspicious_sections[r]))
            return True
        else:
            return False

    def check_section_entropy(self, pe):
        res = []
        for s in pe.sections:
            if s.get_entropy() < 1  or s.get_entropy() > 7:
                res.append([s.Name.decode('utf-8', 'ignore').strip('\x00'), s.get_entropy()])

        if len(res) > 0:
            if len(res) == 1:
                print("[+] Suspicious section's entropy: %s - %.3f" % ( res[0][0], res[0][1]))
            else:
                print("[+] Suspicious entropy in the following sections:")
                for r in res:
                    print("\t- %s - %3f" % (r[0], r[1]))
            return True
        else:
            return False

    def check_imphash(self, pe):
        """Check imphash in a list of known import hashes"""
        ih = pe.get_imphash()
        if ih in self.imphashes:
            print("[+] Known suspicious import hash: %s" % (self.imphashes[ih]))
            return True
        return False

    def check_pe_size(self, pe, data):
        """Check for extra data in the PE file by comparing PE info and data size"""
        length = max(map(lambda x: x.PointerToRawData + x.SizeOfRawData, pe.sections))
        if length < len(data):
            print("[+] %i extra bytes in the file" % (len(data) - length))
            return True
        else:
            return False

    def check_pe_sections(self, pe):
        """Search for PE headers at the beginning of sections"""
        res = []
        for section in pe.sections:
            if b"!This program cannot be run in DOS mode" in section.get_data()[:400] or\
                    b"This program must be run under Win32" in section.get_data()[:400]:
                res.append(section.Name.decode('utf-8').strip('\x00'))

        if len(res) > 0:
            print("[+] PE header in sections %s" % " ".join(res))
            return True
        return False

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
            return True
        return False

    def check_peid(self, data):
        """Check on PEid signatures"""
        peid_db = os.path.dirname(os.path.realpath(__file__))[:-7] + "data/PeID.yara"
        rules = yara.compile(filepath=peid_db)
        matches = rules.match(data=data)
        if len(matches) > 0:
            print("[+] PeID packer: %s" % ", ".join([a.rule for a in matches]))
            return True
        return False

    def check_timestamp(self, pe):
        date = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        if (date.year < 2005) or (date > datetime.datetime.now()):
            print("[+] Suspicious timestamp : %s" % str(date))
            return True
        return False

    def resource(self, pe, r, parents):
        """Recursive printing of resources"""
        if hasattr(r, "data"):
            # Resource
            offset = r.data.struct.OffsetToData
            size = r.data.struct.Size
            data = pe.get_memory_mapped_image()[offset:offset+size]
            if data.startswith(b'\x4d\x5a\x90\x00\x03\x00\x00\x00'):
                if r.name:
                    name = '/'.join(parents) + '/' + str(r.name)
                else:
                    name = '/'.join(parents) + '/' + str(r.id)
                print('[+] PE header in resource {}'.format(name))
                return True
            else:
                return False
        else:
            # directory
            parents = copy.copy(parents)
            suspicious = False
            if r.id is not None:
                parents.append(str(r.id))
            else:
                name = r.name.string.decode('utf-8')
                parents.append(name)
                if name in self.resource_names:
                    print("[+] Suspicious resource name: {} -> {}".format(
                        name,
                        self.resource_names[name])
                    )
                    suspicious = True
            for r2 in r.directory.entries:
                suspicious |= self.resource(pe, r2, parents)
            return suspicious

    def check_pe_resource(self, pe):
        """
        Check if any resource starts with a PE header
        """
        suspicious = False
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for r in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                suspicious |= self.resource(pe, r, [])
        return suspicious

    def run(self, args, pe, data):
        print("Running checks on %s:" % args.PEFILE)
        suspicious = False
        suspicious |= self.check_abnormal_section_name(pe)
        suspicious |= self.check_section_entropy(pe)
        suspicious |= self.check_known_suspicious_sections(pe)
        suspicious |= self.check_pe_size(pe, data)
        suspicious |= self.check_tls(pe)
        suspicious |= self.check_pe_sections(pe)
        suspicious |= self.check_peid(data)
        suspicious |= self.check_imphash(pe)
        suspicious |= self.check_pe_resource(pe)
        if not suspicious:
            print("Nothing suspicious found")
