# PEcli

Tool to analyze PE files in python 3. Current features :
* Show information about the file (import, exports, resources)
* Search for interesting information in the file (abnormal resources, peid...)
* Dump sections or resources
* Check size
* Search for a string in the file

## Installation

You can install it from [pypi](https://pypi.org/project/pecli/) : `pip install pecli`

Or directly from the code :
```
git clone https://github.com/Te-k/pecli.git
cd pecli
pip install .
```

## How to

PEcli works with plugins, like `pecli PLUGIN FILE`

```
usage: pecli [-h] {dump,info,checksize,sig,shell,check,search,richpe,vt} ...

positional arguments:
  {dump,info,checksize,sig,shell,check,search,richpe,vt}
                        Plugins
    dump                Dump resource or section of the file
    info                Extract info from the PE file
    checksize           Check size of the PE file
    sig                 Handle PE Signature
    shell               Launch ipython shell to analyze the PE file
    check               Check for stuff in the file
    search              Search for a string in a PE file
    richpe              Decode Rich PE Header
    vt                  Check PE information in VirusTotal
```

Example :
```
$ pecli info explorer.exe
Metadata
================================================================================
MD5:           418045a93cd87a352098ab7dabe1b53e
SHA1:          98b9ad668e0727be888b861f49aac0f72725e634
SHA256:        81419093ccb985da284931fa3df41c4cfe25350db1c366792903411819371664
Imphash:       c3eb9567e9430e65e703dca7bb8343fa
Size:          1036800 bytes
Type:          PE32 executable (GUI) Intel 80386, for MS Windows
Compile Time:  2008-04-13 19:17:04 (UTC - 0x48025C30)
Entry point:   0x101a55f (section .text)
Debug Information: explorer.pdb

Sections
================================================================================
Name       VirtSize  VirtAddr  RawSize   RawAddr   Entropy  md5
.text      0x44c09   0x1000    0x400     0x44e00   6.3838   8c58c76b600f5aee7f7c7242454b9a1f
.data      0x1db4    0x46000   0x45200   0x1800    1.2992   983f35021232560eaaa99fcbc1b7d359
.rsrc      0xb2f64   0x48000   0x46a00   0xb3000   6.6381   f7df812e2e64b1514d61a9681fbe71da
.reloc     0x374c    0xfb000   0xf9a00   0x3800    6.7817   ec335057489badbf6d8142b57175fd91


Imports
================================================================================
ADVAPI32.dll
	0x1001000 RegSetValueW
	0x1001004 RegEnumKeyExW
	0x1001008 GetUserNameW
[SNIP]

Resources:
================================================================================
Id           Name    Size      Lang           Sublang           Type           MD5
2-143-1031   None    2040 B    LANG_GERMAN    SUBLANG_GERMAN    data           f0e8e299c637633db0a5af11042adb04
2-145-1031   None    35322 B   LANG_GERMAN    SUBLANG_GERMAN    data           1e5bfaf34503ce750b3cc13058a3f88b
2-146-1031   None    12826 B   LANG_GERMAN    SUBLANG_GERMAN    data           061daf6ef2047f33947d5655f1c8aaa4
[SNIP]
```

```
$ pecli check playlib.exe
Running checks on playlib.exe:
[+] Abnormal section names: .enigma1 .enigma2
[+] Suspicious section's entropy: .enigma1 - 7.931
[+] Known malicious sections
	-.enigma1: Enigma Virtual Box protector
	-.enigma2: Enigma Virtual Box protector
[+] 200 extra bytes in the file
[+] TLS Callback: 0x446bb0
[+] PE header in sections .enigma2
[+] Known suspicious import hash: Enigma VirtualBox
```

## License

This tool is published under MIT License

## Similar tools

* [Viper](https://viper.li/)
* [PEScanner](https://github.com/Te-k/analyst-scripts/blob/master/pe/pescanner.py) published by Michael Ligh for the [Malware Analyst's Cookbook](https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD%3A+Tools+and+Techniques+for+Fighting+Malicious+Code-p-9780470613030) (python2 only)
* [Manalyze](https://github.com/JusticeRage/Manalyze) by Ivan Kwiatkowski
* On Windows, [PeStudio](https://www.winitor.com/), [PEView](http://wjradburn.com/software/) and [Resource Hacker](http://www.angusj.com/resourcehacker/)
