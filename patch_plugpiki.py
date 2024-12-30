import binascii
import collections
import csv
import lief
import struct
import sys

BASE_ADDR = 0x10000000
I18N_ADDR = 0x004ea000

def section_search(section: lief.Section, data: bytes, location: int = 0):
    locations = list()
    while location := section.search(data, location):
        locations.append(BASE_ADDR + section.virtual_address + location)
        location += len(data)
    return locations
#

def address_in_replaced_ranges(replaced_ranges: list, address: int):
    for virtual_address, size in replaced_ranges:
        if address >= virtual_address and address < virtual_address + size:
            return True
    return False
#

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args

    pe = lief.PE.parse("./plugins/plugPiki.dll")
    csvfile = csv.reader(open("./JPN to ENG.csv"))
    
    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    for row in csvfile:
        if len(row) < 2:
            continue
        
        old = row[0]; old_sjis = old.encode("sjis") + b'\0'
        new = row[1]; new_sjis = new.encode("sjis") + b'\0'

        if not (old_locations := section_search(rdata, old_sjis)):
            if verbose: print(f"Message \"{old}\" was not found!")
            continue

        if not (search_results := [(old_location, xrefs) for old_location in old_locations if (xrefs := pe.xref(old_location))]):
            if verbose: print(f"Message \"{old}\" at 0x{old_location:x} ({binascii.hexlify(old_sjis)}) is not xref'd")
            continue

        for old_location, xrefs in search_results:
            if len(xrefs) != 1:
                if verbose: print(f"Message \"{old}\" at 0x{old_location:x} ({binascii.hexlify(old_sjis)}) was xref'd in {len(xrefs)} places: {xrefs}")
            for address in xrefs:
                pe.patch_address(BASE_ADDR + address, tuple(struct.pack("<I", cursor)))

        i18n_blob += new_sjis
        cursor += len(new_sjis)

    i18n = lief.PE.Section(".i18n")
    i18n.content = i18n_blob
    i18n.virtual_address = I18N_ADDR

    pe.add_section(i18n, lief.PE.SECTION_TYPES.DATA)
    pe.write("./files/plugins/plugPiki.dll")
#

if __name__ == "__main__":
    main(sys.argv)
