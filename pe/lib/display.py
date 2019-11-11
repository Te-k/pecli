import hashlib

def display_sections(pe):
    """Display information about the PE sections"""
    print("%-10s %-9s %-9s %-9s %-9s %-8s %s" % ( "Name", "VirtSize", "VirtAddr", "RawAddr", "RawSize", "Entropy", "md5"))
    for section in pe.sections:
        name = section.Name.decode('utf-8', 'ignore').strip('\x00')
        m = hashlib.md5()
        m.update(section.get_data())
        print("%-10s %-9s %-9s %-9s %-9s %-8.04f %s" % (
            name,
            hex(section.Misc_VirtualSize),
            hex(section.VirtualAddress),
            hex(section.PointerToRawData),
            hex(section.SizeOfRawData),
            section.get_entropy(),
            m.hexdigest()
        ))
    print("")
