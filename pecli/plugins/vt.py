#! /usr/bin/env python
import sys
import os
import hashlib
import pefile
import configparser
import json
import ssdeep
from pecli.plugins.base import Plugin
from pecli.lib.dotnet_guid import get_guid, is_dot_net_assembly
from pecli.lib.utils import debug_filename, debug_guid
from virus_total_apis import PublicApi, PrivateApi


class PluginVirusTotal(Plugin):
    name = "vt"
    description = "Check PE information in VirusTotal"
    on_pe = False

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='Subcommand')
        parser_a = subparsers.add_parser('check', help='Check if the binary is in VT')
        parser_a.add_argument('PEFILE', help='a PE file')
        parser_a.set_defaults(subcommand='check')
        parser_a.add_argument('--raw', '-r', help='Raw data', action='store_true')
        parser_b = subparsers.add_parser('similar', help='Check for similar files in VT')
        parser_b.add_argument('PEFILE', help='a PE file')
        parser_b.set_defaults(subcommand='similar')
        parser_c = subparsers.add_parser('config', help='Configure VirusTotal API key')
        parser_c.add_argument('APIKEY', help='API Key')
        parser_c.add_argument('--type', help='API Type', choices=['private', 'public'], default='private')
        parser_c.set_defaults(subcommand='config')
        self.parser = parser

    def read_config(self, path):
        """
        Read VT API configuration
        """
        config = configparser.ConfigParser()
        config.read(path)
        return config['vt']

    def print_results(self, res, sha256):
        """
        Print VT search results
        """
        if res['response_code'] != 200:
            print("Something went wrong, response code {}".format(res['response_code']))
            sys.exit(-1)
        if 'hashes' not in res['results']:
            print('No sample found')
        elif res['results']['hashes'] == [sha256]:
            print('No other sample found')
        else:
            if sha256 in res['results']['hashes']:
                print('{} samples found'.format(len(res['results']['hashes']) - 1))
            else:
                print('{} samples found'.format(len(res['results']['hashes'])))
            if len(res['results']['hashes']) < 15:
                for h in res['results']['hashes']:
                    if h != sha256:
                        print(h)

    def run(self, args):
        config_path = os.path.join(os.path.expanduser("~"), ".vtapi")
        if hasattr(args, 'subcommand'):
            if args.subcommand in('check', 'similar'):
                if not os.path.isfile(config_path):
                    print("Invalid configuration file, please use pe vt config to configure your VT account")
                    sys.exit(1)
                cf = self.read_config(config_path)
                if cf['type'] == 'private':
                    vt = PrivateApi(cf['apikey'])
                else:
                    vt = PublicApi(cf['apikey'])
                if args.subcommand == 'check':
                    with open(args.PEFILE, 'rb') as f:
                        data = f.read()
                    m = hashlib.sha256()
                    m.update(data)
                    sha256 = m.hexdigest()
                    response = vt.get_file_report(sha256)
                    if args.raw:
                        print(json.dumps(response, sort_keys=False, indent=4))
                    else:
                        if response["response_code"] != 200:
                            print("Error with the request (reponse code %i)" % response["response_code"])
                            sys.exit(1)

                        if response["results"]["response_code"] == 0:
                            print("File not found")
                        else:
                            print("[+] Detection: %i / %i" % (
                                    response["results"]["positives"],
                                    response["results"]["total"]
                                )
                            )
                            print("[+] MD5: %s" % response["results"]["md5"])
                            print("[+] SHA1: %s" % response["results"]["sha1"])
                            print("[+] SHA256: %s" % response["results"]["sha256"])
                            if "first_seen" in response['results']:
                                print("[+] First Seen: %s" % response["results"]["first_seen"])
                            if "last_seen" in response['results']:
                                print("[+] Last Seen: %s" % response["results"]["last_seen"])
                            print("[+] Link: %s" % response["results"]["permalink"])
                elif args.subcommand == 'similar':
                    if cf['type'] != 'private':
                        print('I am sorry, you need a private VT access to do that')
                        sys.exit(1)
                    with open(args.PEFILE, 'rb') as f:
                        data = f.read()
                    m = hashlib.sha256()
                    m.update(data)
                    sha256 = m.hexdigest()
                    # Check if this PE file is in VT first
                    response = vt.get_file_report(sha256)
                    if response["results"]["response_code"] == 0:
                        print("File not in VT, computing imphash, ssdeep only")
                        pe = pefile.PE(data=data)
                        imphash = pe.get_imphash()
                        ssd = ssdeep.hash(data)
                        vhash = None
                        authentihash = None
                        dbg_filename = debug_filename(pe)
                        dbg_guid = debug_guid(pe)
                        if is_dot_net_assembly(pe):
                            res = get_guid(pe, data)
                            dotnet_mvid = res["mvid"]
                            dotnet_typelib = res["typelib_id"]
                        else:
                            dotnet_mvid = None
                            dotnet_typelib = None
                    else:
                        print("File identified in VT: {}".format(response['results']['permalink']))
                        vhash = response['results']['vhash']
                        ssd = response['results']['ssdeep']
                        authentihash = response['results']['authentihash']
                        imphash = response['results']['additional_info']["pe-imphash"]
                        dbg_guid = None
                        dbg_filename = None
                        if "pe-debug" in response['results']['additional_info']:
                            if "codeview" in response['results']['additional_info']["pe-debug"][0]:
                                if "guid" in response['results']['additional_info']["pe-debug"][0]["codeview"]:
                                    dbg_guid = response['results']['additional_info']["pe-debug"][0]["codeview"]["guid"]
                                if "name" in response['results']['additional_info']["pe-debug"][0]["codeview"]:
                                    dbg_filename = response['results']['additional_info']['pe-debug'][0]['codeview']['name']

                        if "netguids" in response['results']['additional_info']:
                            dotnet_mvid = response['results']['additional_info']['netguids']['mvid']
                            dotnet_typelib = response['results']['additional_info']['netguids']['typelib_id']
                        else:
                            dotnet_mvid = None
                            dotnet_typelib = None

                    # Start with imphash
                    print("# Searching for imphash: {}".format(imphash))
                    res = vt.file_search('imphash:"{}"'.format(imphash))
                    self.print_results(res, sha256)
                    # ssdeep
                    print("# Searching for ssdeep: {}".format(ssd))
                    res = vt.file_search('ssdeep:"{}"'.format(ssd))
                    self.print_results(res, sha256)
                    # authentihash
                    if authentihash:
                        print("# Searching for authentihash: {}".format(authentihash))
                        res = vt.file_search('authentihash:"{}"'.format(authentihash))
                        self.print_results(res, sha256)
                    # vhash
                    if vhash:
                        print("# Searching for vhash: {}".format(vhash))
                        res = vt.file_search('vhash:"{}"'.format(vhash))
                        self.print_results(res, sha256)
                    # .NET GUIDs
                    if dotnet_mvid:
                        print("# Searching for .NET Module Version id: {}".format(dotnet_mvid))
                        res = vt.file_search('netguid:"{}"'.format(dotnet_mvid))
                        self.print_results(res, sha256)
                    if dotnet_typelib:
                        print("# Searching for .NET TypeLib id: {}".format(dotnet_typelib))
                        res = vt.file_search('netguid:"{}"'.format(dotnet_typelib))
                        self.print_results(res, sha256)
                    # Debug
                    if dbg_filename:
                        print("# Searching for Debug Filename: {}".format(dbg_filename))
                        res = vt.file_search('"{}"'.format(dbg_filename))
                        self.print_results(res, sha256)
                    if dbg_guid:
                        print("# Searching for Debug GUID: {}".format(dbg_guid))
                        res = vt.file_search('"{}"'.format(dbg_guid))
                        self.print_results(res, sha256)
            elif args.subcommand == 'config':
                config = configparser.ConfigParser()
                if args.type == 'public':
                    config['vt'] = {
                        'intelligence': False,
                        'engines': '',
                        'timeout': 60,
                        'apikey': args.APIKEY,
                        'type': 'public'
                    }
                else:
                    config['vt'] = {
                        'intelligence': True,
                        'engines': '',
                        'timeout': 60,
                        'apikey': args.APIKEY,
                        'type': 'private'
                    }
                with open(config_path, 'w') as configfile:
                    config.write(configfile)
                print("Config file {} updated".format(config_path))
            else:
                self.parser.print_help()
        else:
            self.parser.print_help()
