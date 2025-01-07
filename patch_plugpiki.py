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

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args

    filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "**/*.csv"), recursive=True)]
    filepaths.sort()  # Filepaths are sorted for determinism.
    rows = accumulate_csvs(filepaths)

    pe = lief.PE.parse("./plugins/plugPiki.dll")

    # Disable "cursor nuki!" panic modal that prevents the pluckaphone from working.
    pe.patch_address(BASE_ADDR + 0xa500d, tuple(b'\x90' * 5))
    pe.patch_address(BASE_ADDR + 0xa5110, tuple(b'\x90' * 5))

    # Disable "TekiPersonality::read:too old version:%d" panic modal that prevents GenObjectTeki version 7 from working.
    pe.patch_address(BASE_ADDR + 0x885cf, tuple(b'\x90' * 5))

    # Disable world freeze when `Controller::keyClick(0x4000) == true` (spacebar).
    pe.patch_address(BASE_ADDR + 0xb4860, tuple(b'\x31\xC0\x90'))  # xor eax, eax; nop

    # Allocate ogRader resources on heap -1 instead of Movie heap to avoid running out of memory.  It running out of memory is an oversight caused by preloadLanguage() being skipped in this version.
    pe.patch_address(BASE_ADDR + 0x22ea8, tuple(b'\x6A\xFF'))  # push -1

    # Set displayPikiCount and onionsDiscovered bitfield to all ones, unlocking all Pikmin and Onions
    pe.patch_address(BASE_ADDR + 0x9abcf, tuple(b'\xc6\x81\xac\x01\x00\x00\xff'))  # displayPikiCount  # mov byte ptr [ecx + 0x1ac], 0xff
    pe.patch_address(BASE_ADDR + 0x9ac20, tuple(b'\xc6\x80\x84\x01\x00\x00\xff'))  # onionsDiscovered  # mov byte ptr [eax + 0x184], 0xff
    pe.patch_address(BASE_ADDR + 0x9ac27, tuple(b'\x90' * 20))                     # Stub the call sites of the functions that would normally set the bitfields.
    # The values are initialized in two places for redundancy, so change both.
    pe.patch_address(BASE_ADDR + 0x9ae36, tuple(b'\xc6\x81\xac\x01\x00\x00\xff'))  # displayPikiCount  # mov byte ptr [ecx + 0x1ac], 0xff
    pe.patch_address(BASE_ADDR + 0x9aef4, tuple(b'\xc6\x80\x84\x01\x00\x00\xff'))  # onionsDiscovered  # mov byte ptr [eax + 0x184], 0xff
    pe.patch_address(BASE_ADDR + 0x9aefb, tuple(b'\x90' * 20))                     # Stub the call sites of the functions that would normally set the bitfields.

    # Initialize PlayerState::mTutorial to false.  This spot is likely in PlayerState::PlayerState().
    pe.patch_address(BASE_ADDR + 0x9af94, tuple(b'\xc6\x82\x85\x01\x00\x00\x00'))  # mov byte ptr ds:[edx + 0x185], 0
    # The value is initialized in two places for redundancy, so change both.  This spot is likely in PlayerState::initGame().
    pe.patch_address(BASE_ADDR + 0x9ac87, tuple(b'\xc6\x82\x85\x01\x00\x00\x00'))  # mov byte ptr ds:[edx + 0x185], 0

    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        # Hack to support inline translation notes in the CSV files.
        if row[0].startswith("i18n"):
            continue

        old_msg = row[0]; old_sjis = old_msg.encode("sjis") + b'\0'

        if not (old_locations := section_search(rdata, old_sjis)):
            print(f"WARNING: Message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) was not found!")
            continue

        if len(old_locations) > 1:
            if verbose: print(f"INFO: Message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) was found at multiple locations! {old_locations}")

        if not (xrefs := [xref for old_location in old_locations if (xref := pe.xref(old_location))]):
            print(f"WARNING: No xrefs for any copy(s) of the message \"{old_msg}\" ({binascii.hexlify(old_sjis)}) were found! {old_locations}")
            continue

        # Stop placeholder rows without translations from cluttering the log with errors
        if len(row) < 2:
            continue

        xrefs_chain = list(itertools.chain.from_iterable(xrefs))
        translations = row[1:]

        if len(xrefs_chain) != len(translations):
            print(f"ERROR: \"{old_msg}\" ({binascii.hexlify(old_sjis)}) requires {len(xrefs_chain)} translations, but {len(translations)} were given!")
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
