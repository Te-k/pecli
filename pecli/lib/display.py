import hashlib

def display_ar(section):
    """
    Show access rights of a section
    """
    res = ""
    if section.IMAGE_SCN_MEM_READ:
        res += "R"
    else:
        res += "-"
    if section.IMAGE_SCN_MEM_WRITE:
        res += "W"
    else:
        res += "-"
    if section.IMAGE_SCN_MEM_EXECUTE:
        res += "X"
    else:
        res += "-"
    return res

def display_sections(pe):
    """Display information about the PE sections"""
    print("{:9} {:4} {:10} {:10} {:9} {:9} {:8} {}".format("Name", "RWX", "VirtSize", "VirtAddr", "RawAddr", "RawSize", "Entropy", "md5"))
    for section in pe.sections:
        name = section.Name.decode('utf-8', 'ignore').strip('\x00')
        m = hashlib.md5()
        m.update(section.get_data())
        print("{:9} {:4} {:10} {:10} {:9} {:9} {:6.2f} {}".format(
            name,
            display_ar(section),
            hex(section.Misc_VirtualSize),
            hex(section.VirtualAddress),
            hex(section.PointerToRawData),
            hex(section.SizeOfRawData),
            section.get_entropy(),
            m.hexdigest()
        ))
    print("")
