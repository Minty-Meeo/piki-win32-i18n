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

def read_new_bin(group: str, string: str):
    try:
        return binascii.unhexlify(string)
    except binascii.Error:
        return open(os.path.join("asm", group, string), "rb").read()
#
