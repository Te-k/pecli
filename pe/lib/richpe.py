import sys
import hashlib
import argparse
from struct import pack


def get_richpe_hash(pe):
    """Computes the RichPE hash given a file path or data.
    If the RichPE hash is unable to be computed, returns None.
    Otherwise, returns the computed RichPE hash.
    If both file_path and data are provided, file_path is used by default.
    Source : https://github.com/RichHeaderResearch/RichPE
    """
    if pe.RICH_HEADER is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = pe.RICH_HEADER.values
    if len(rich_fields) % 2 != 0:
        return None

    # The RichPE hash of a file is computed by computing the md5 of specific
    # metadata within  the Rich header and the PE header
    md5 = hashlib.md5()

    # Update hash using @Comp.IDs and masked counts from Rich header
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        mask = 2 ** (count.bit_length() // 2 + 1) - 1
        count |= mask
        md5.update(pack("<L", compid))
        md5.update(pack("<L", count))

    # Update hash using metadata from the PE header
    md5.update(pack("<L", pe.FILE_HEADER.Machine))
    md5.update(pack("<L", pe.FILE_HEADER.Characteristics))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.Subsystem))
    md5.update(pack("<B", pe.OPTIONAL_HEADER.MajorLinkerVersion))
    md5.update(pack("<B", pe.OPTIONAL_HEADER.MinorLinkerVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorImageVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorImageVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    md5.update(pack("<L", pe.OPTIONAL_HEADER.MinorSubsystemVersion))

    return md5.hexdigest()
