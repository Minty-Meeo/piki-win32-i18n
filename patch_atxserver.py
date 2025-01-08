import collections
import glob
import lief
import sys

import i18n_helpers

BASE_ADDR = 0x10000000

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args
    pe = lief.PE.parse("./plugins/plugAtxServer.dll")

    filepaths = [filename for filename in glob.glob("patch/atxserver/**/*.csv", recursive=True)]
    i18n_helpers.sniff_search_patch(verbose, "atxserver", pe, pe.get_section(".text"), i18n_helpers.accumulate_csvs(filepaths), BASE_ADDR)
    
    pe.write("./files/plugins/plugAtxServer.dll")    
#

if __name__ == "__main__":
    main(sys.argv)
