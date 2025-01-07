import codecs
import collections
import csv
import glob
import lief
import os
import sys

LANGUAGE = "eng"
BASE_ADDR = 0x10000000

def accumulate_source_messages(filepaths: list[str]):
    messages = set[str]()
    for filepath in filepaths:
        for row in csv.reader(open(filepath)):
            if len(row) < 1:
                continue
            if row[0].startswith("i18n"):
                continue
            # CSV doesn't support C escape sequences, and I don't feel like switching to a more sophisticated database format.
            messages.add(codecs.escape_decode(row[0])[0].decode())
    return messages
#

def main(args: collections.abc.Sequence[str]):
    elimination_mode = "-e" in args or "--eliminaton" in args
    
    if elimination_mode:
        filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "*.csv"))]
        filepaths.sort()  # Filepaths are sorted for determinism.
        messages = accumulate_source_messages(filepaths)

    pe = lief.PE.parse("./plugins/plugPiki.dll")
    rdata = pe.get_section(".rdata")

    for address in range(BASE_ADDR + rdata.virtual_address, BASE_ADDR + rdata.virtual_address + rdata.size, 4):
        # Is something at this address xref'd ?
        if not (xrefs := pe.xref(address)):
            continue
        
        # Read until null terminator, however long it takes.
        end = address
        while int.from_bytes(pe.get_content_from_virtual_address(end, 1)):
            end += 1
        
        # C-Strings pad null characters to a multiple of 4.  Might just be a concidence, but check anyway.
        if any(pe.get_content_from_virtual_address(end, 4 - end % 4)):
            continue
        
        # Is what was found a valid shift-jis string?
        try:
            old_sjis = pe.get_content_from_virtual_address(address, end - address)
            old_utf8 = str(old_sjis, encoding="sjis")
        except UnicodeError:
            continue

        # Can this string safely round-trip into US-ASCII?  I don't care about those.
        try:
            old_utf8.encode("ascii")
            continue
        except UnicodeError:
            pass

        # Is this message already accounted for?
        if elimination_mode and old_utf8 in messages:
            continue

        # Another xref in the middle of this supposed string seems unlikely... skip it if one is found.
        midstring_xref = False
        for i in range(address + 4, end, 4):
            if pe.xref(i):
                midstring_xref = True
                break
        if midstring_xref:
            continue

        print(f"{address:x}: {repr(old_utf8)} {xrefs}")
#

if __name__ == "__main__":
    main(sys.argv)
