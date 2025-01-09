import binascii
import codecs
import csv
import itertools
import lief
import os
import struct

def accumulate_csvs(filepaths: list[str]):
    rows = list()
    for filepath in filepaths:
        for row in csv.reader(open(filepath)):
            # Most software refuses to write jagged CSV files, so trailing empty cells must be removed.  Aditionally, CSV
            # doesn't support C escape sequences, and I don't feel like switching to a more sophisticated database format.
            rows.append([codecs.escape_decode(cell)[0].decode() for cell in row if cell])
    return rows
#

def accumulate_csvs_first_column(filepaths: list[str]):
    messages = set[str]()
    for filepath in filepaths:
        for row in csv.reader(open(filepath)):
            if len(row) < 1:
                continue
            # CSV doesn't support C escape sequences, and I don't feel like switching to a more sophisticated database format.
            messages.add(codecs.escape_decode(row[0])[0].decode())
    return messages
#

def section_search(section: lief.Section, data: bytes, base_address: int, location: int = 0):
    locations = list()
    while location := section.search(data, location):
        locations.append(base_address + section.virtual_address + location)
        location += len(data)
    return locations
#

def acquire_bytes(group: str, string: str):
    if string.startswith('!'):
        return binascii.unhexlify(string[1:3]) * int(string[4:])
    try:
        return binascii.unhexlify(string)
    except binascii.Error:
        return open(os.path.join("asm", group, string), "rb").read()
#

def xrefd_string_replace(verbose: bool, group: str, pe: lief.PE, section: lief.Section, rows: list, base_address: int, i18n_address: int):
    i18n_blob = bytearray()
    cursor = base_address + i18n_address

    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        # Hack to support inline translation notes in the CSV files.
        if row[0].startswith("i18n"):
            continue

        old_msg = row[0]; old_sjis = old_msg.encode("sjis") + b'\0'

        if not (old_locations := section_search(section, old_sjis, base_address)):
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
            pe.patch_address(base_address + address, tuple(struct.pack("<I", cursor)))
            i18n_blob += new_utf8
            cursor += len(new_utf8)

    i18n = lief.PE.Section(".i18n")
    i18n.content = i18n_blob
    i18n.virtual_address = i18n_address

    pe.add_section(i18n, lief.PE.SECTION_TYPES.DATA)
#

def sniff_search_patch(verbose: bool, group: str, pe: lief.PE, section: lief.Section, rows: list, base_address: int):
    for row in rows:
        if len(row) < 1:
            print(f"WARNING: There was an empty row in a file!")
            continue

        scent = binascii.unhexlify(row[0])

        if not (locations := section_search(section, scent, base_address)):
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
        known_bin = acquire_bytes(group, row[2])

        found_bin = pe.get_content_from_virtual_address(address, len(known_bin))
        if not known_bin == found_bin:
            print(f"ERROR: Bytes found at {address:x} ({binascii.hexlify(found_bin)}) don't match known bytes! ({binascii.hexlify(known_bin)})")
            continue

        # Stop placeholder rows with incomplete patch definitions
        if len(row) < 4:
            if verbose: print(f"INFO: There was an incomplete row in a file!")
            continue

        new_bin = acquire_bytes(group, row[3])
        if not len(known_bin) == len(new_bin):
            print(f"ERROR: New bytes are not the same length! known: {len(known_bin)}, new: {len(new_bin)}")
            continue

        pe.patch_address(address, tuple(new_bin))
#
