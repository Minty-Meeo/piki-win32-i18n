import collections
import glob
import lief
import os
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

    filepaths = [filename for filename in glob.glob(os.path.join(LANGUAGE, "**/*.csv"), recursive=True)]
    filepaths.sort()  # Filepaths are sorted for determinism.
    i18n_helpers.xrefd_string_replace(verbose, "plugpiki", pe, pe.get_section(".rdata"), i18n_helpers.accumulate_csvs(filepaths), BASE_ADDR, I18N_ADDR)
    
    pe.write("./files/plugins/plugPiki.dll")
#

if __name__ == "__main__":
    main(sys.argv)
