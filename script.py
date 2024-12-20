import csv
import lief
import struct

BASE_ADDR = 0x10000000
I18N_ADDR = 0x004ea000

def main():
    pe = lief.PE.parse("./plugins/plugPiki.dll")
    csvfile = csv.reader(open("./JPN to ENG.csv"))
    
    rdata = pe.get_section(".rdata")
    i18n_blob = bytearray()
    cursor = BASE_ADDR + I18N_ADDR

    for row in csvfile:
        if len(row) < 2:
            continue
        string_location = BASE_ADDR + rdata.virtual_address + rdata.search(row[0].encode("shift-jis"))
        eng_bytes = row[1].encode()
        for address in pe.xref(string_location):
            pe.patch_address(BASE_ADDR + address, tuple(struct.pack("<I", cursor)))
        i18n_blob += eng_bytes + b'\0'
        cursor += len(eng_bytes) + 1

    i18n = lief.PE.Section(".i18n")
    i18n.content = i18n_blob
    i18n.virtual_address = I18N_ADDR

    pe.add_section(i18n, lief.PE.SECTION_TYPES.DATA)
    pe.write("./files/plugins/plugPiki.dll")
#

if __name__ == "__main__":
    main()
