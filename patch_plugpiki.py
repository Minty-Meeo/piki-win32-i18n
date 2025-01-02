import binascii
import collections
import csv
import glob
import itertools
import lief
import os
import struct
import sys

LANGUAGE = "eng"
BASE_ADDR = 0x10000000
I18N_ADDR = 0x004ea000

def accumulate_csvs(filepaths: list[str]):
    rows = list()
    for filepath in filepaths:
        for row in csv.reader(open(filepath)):
            # Most software refuses to write jagged CSV files, so trailing empty cells must be removed.
            rows.append([cell for cell in row if cell])
    return rows
#

def section_search(section: lief.Section, data: bytes, location: int = 0):
    locations = list()
    while location := section.search(data, location):
        locations.append(BASE_ADDR + section.virtual_address + location)
        location += len(data)
    return locations
#

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args

    filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "*.csv"))]
    filepaths.sort()  # Filepaths are sorted for determinism.
    rows = accumulate_csvs(filepaths)

    pe = lief.PE.parse("./plugins/plugPiki.dll")
    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        if len(row) < 2:
            continue  # Stops placeholder rows without translations from cluttering the log with errors

        old_msg = row[0]; old_sjis = old_msg.encode("sjis") + b'\0'

        if not (old_locations := section_search(rdata, old_sjis)):
            print(f"WARNING: Message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) was not found!")
            continue

        if len(old_locations) > 1:
            if verbose: print(f"INFO: Message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) was found at multiple locations! {old_locations}")

        if not (xrefs := [xref for old_location in old_locations if (xref := pe.xref(old_location))]):
            print(f"WARNING: No xrefs for any copy(s) of the message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) were found! {old_locations}")
            continue

        xrefs_chain = list(itertools.chain.from_iterable(xrefs))
        translations = row[1:]

        if len(xrefs_chain) != len(translations):
            print(f"ERROR: \"{old_msg}\" requires {len(xrefs_chain)} translations, but {len(translations)} were given!")
            continue
        
        for address, new_msg in zip(xrefs_chain, translations):
            new_sjis = new_msg.encode("sjis") + b'\0'
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
