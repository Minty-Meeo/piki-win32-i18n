.intel_syntax noprefix
mov edx, dword ptr ss:[ebp-0x04]  # EDX = CoreNode ptr from stack
mov eax, dword ptr ss:[ebp-0x114] # EAX = psizl.cx from stack
add eax, 16                       # Add +16 to width.  This seems to line the message up with the +20 padding for slider widgets.
mov dword ptr ds:[edx+0x4C], eax  # combo_display_x = EAX
ret
