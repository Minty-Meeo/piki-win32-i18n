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

import i18n_helpers

LANGUAGE = "eng"
BASE_ADDR = 0x10000000
I18N_ADDR = 0x004ea000

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args
    pe = lief.PE.parse("./plugins/plugPiki.dll")

    filepaths = [filename for filename in glob.glob("patch/plugpiki/**/*.csv", recursive=True)]
    i18n_helpers.sniff_search_patch(verbose, "plugpiki", pe, pe.get_section(".text"), i18n_helpers.accumulate_csvs(filepaths), BASE_ADDR)

    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "**/*.csv"), recursive=True)]
    filepaths.sort()  # Filepaths are sorted for determinism.
    rows = i18n_helpers.accumulate_csvs(filepaths)

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        # Hack to support inline translation notes in the CSV files.
        if row[0].startswith("i18n"):
            continue

        old_msg = row[0]; old_sjis = old_msg.encode("sjis") + b'\0'

        if not (old_locations := i18n_helpers.section_search(rdata, old_sjis, BASE_ADDR)):
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
