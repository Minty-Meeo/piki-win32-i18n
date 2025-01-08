import binascii
import codecs
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
            # Most software refuses to write jagged CSV files, so trailing empty cells must be removed.  Aditionally, CSV
            # doesn't support C escape sequences, and I don't feel like switching to a more sophisticated database format.
            rows.append([codecs.escape_decode(cell)[0].decode() for cell in row if cell])
    return rows
#

def section_search(section: lief.Section, data: bytes, location: int = 0):
    locations = list()
    while location := section.search(data, location):
        locations.append(BASE_ADDR + section.virtual_address + location)
        location += len(data)
    return locations
#

def read_new_bin(group: str, string: str):
    try:
        return binascii.unhexlify(string)
    except binascii.Error:
        return open(os.path.join("asm", group, string), "rb").read()
#

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args
    pe = lief.PE.parse("./plugins/plugPiki.dll")

    text = pe.get_section(".text")
    filepaths = [filename for filename in glob.glob("patch/plugpiki/**/*.csv", recursive=True)]
    rows = accumulate_csvs(filepaths)

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        scent = binascii.unhexlify(row[0])

        if not (locations := section_search(text, scent)):
            print(f"ERROR: Scent ({binascii.hexlify(scent)}) was not found!")
            continue

        if len(locations) > 1:
            print(f"ERROR: Scent ({binascii.hexlify(scent)}) was found at multiple locations! {locations}")
            continue

        # Stop placeholder rows with incomplete patch definitions
        if len(row) < 3:
            if verbose: print(f"INFO: There was an incomplete row in a file!")
            continue

        address = locations[0] + int(row[1])
        known_bin = binascii.unhexlify(row[2])

        found_bin = pe.get_content_from_virtual_address(address, len(known_bin))
        if not known_bin == found_bin:
            print(f"ERROR: Bytes found at {address:x} ({binascii.hexlify(found_bin)}) don't match known bytes! ({binascii.hexlify(known_bin)})")
            continue

        # Stop placeholder rows with incomplete patch definitions
        if len(row) < 4:
            if verbose: print(f"INFO: There was an incomplete row in a file!")
            continue

        new_bin = read_new_bin("plugpiki", row[3])
        if not len(known_bin) == len(new_bin):
            print(f"ERROR: New bytes are not the same length! known: {len(known_bin)}, new: {len(new_bin)}")
            continue

        pe.patch_address(address, tuple(new_bin))

    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "**/*.csv"), recursive=True)]
    filepaths.sort()  # Filepaths are sorted for determinism.
    rows = accumulate_csvs(filepaths)

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        # Hack to support inline translation notes in the CSV files.
        if row[0].startswith("i18n"):
            continue

        old_msg = row[0]; old_sjis = old_msg.encode("sjis") + b'\0'

        if not (old_locations := section_search(rdata, old_sjis)):
            print(f"WARNING: Message {repr(old_msg)} ({binascii.hexlify(old_sjis)}) was not found!")
            continue

        if len(old_locations) > 1:
            if verbose: print(f"INFO: Message {repr(old_msg)} ({binascii.hexlify(old_sjis)}) was found at multiple locations! {old_locations}")

        if not (xrefs := [xref for old_location in old_locations if (xref := pe.xref(old_location))]):
            print(f"WARNING: No xrefs for any copy(s) of the message {repr(old_msg)} ({binascii.hexlify(old_sjis)}) were found! {old_locations}")
            continue

        # Stop placeholder rows without translations from cluttering the log with errors
        if len(row) < 2:
            continue

        xrefs_chain = list(itertools.chain.from_iterable(xrefs))
        translations = row[1:]

        if len(xrefs_chain) != len(translations):
            print(f"ERROR: {repr(old_msg)} ({binascii.hexlify(old_sjis)}) requires {len(xrefs_chain)} translations, but {len(translations)} were given!")
            continue
        
        for address, new_msg in zip(xrefs_chain, translations):
            new_utf8 = new_msg.encode("utf8") + b'\0'
            pe.patch_address(BASE_ADDR + address, tuple(struct.pack("<I", cursor)))
            i18n_blob += new_utf8
            cursor += len(new_utf8)

    i18n = lief.PE.Section(".i18n")
    i18n.content = i18n_blob
    i18n.virtual_address = I18N_ADDR

    pe.add_section(i18n, lief.PE.SECTION_TYPES.DATA)
    pe.write("./files/plugins/plugPiki.dll")
#

if __name__ == "__main__":
    main(sys.argv)
