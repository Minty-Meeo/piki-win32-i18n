import binascii
import codecs
import csv
import lief
import os

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

def sniff_search_patch(verbose, group: str, pe: lief.PE, section: lief.Section, rows: list, base_address: int):
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
