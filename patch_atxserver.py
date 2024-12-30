import collections
import lief
import sys

BASE_ADDR = 0x10000000

def main(args: collections.abc.Sequence[str]):
    verbose = "-v" in args or "--verbose" in args

    pe = lief.PE.parse("./plugins/plugAtxServer.dll")

    # Modify call to `UIWindow::sizeWindow` to adjust the initial width of the AgeView's right pane.
    pe.patch_address(BASE_ADDR + 0x7350, tuple(b'\x68\x30\x02\x00\x00'))  # push 0x230
    
    # Overwrite `_chkesp` call after `GetTextExtentPoint32A` call.
    pe.patch_address(BASE_ADDR + 0xB6BD, tuple(b'\xE8\x1E\x04\x00\x00'))  # call +0x41E  ; To where MenuSliderAdjust routine is stored
    with open("./asm/MenuSliderAdjust.bin", "rb") as f:
        pe.patch_address(BASE_ADDR + 0xBAE0, tuple(f.read()))
    
    pe.write("./files/plugins/plugAtxServer.dll")
#

if __name__ == "__main__":
    main(sys.argv)
