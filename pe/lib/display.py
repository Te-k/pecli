import hashlib

def display_sections(pe):
    """Display information about the PE sections"""
    print("%-10s %-11s %-11s %-11s %-11s %s" % ( "Name", "VirtualSize", "VirtualAddr", "RawSize", "RawAddress", "md5"))
    for section in pe.sections:
        name = section.Name.decode('utf-8').strip('\x00')
        m = hashlib.md5()
        m.update(section.get_data())
        print("%-10s %-11s %-11s %-11s %-11s %s" % (
            name,
            hex(section.Misc_VirtualSize),
            hex(section.VirtualAddress),
            hex(section.PointerToRawData),
            hex(section.SizeOfRawData),
            m.hexdigest()
        ))
    print("")
