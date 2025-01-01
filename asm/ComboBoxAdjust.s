.intel_syntax noprefix
mov edx, dword ptr ss:[ebp-0x04]  # EDX = CoreNode ptr from stack
mov eax, dword ptr ss:[ebp-0x114] # EAX = psizl.cx from stack
add eax, 20                       # Add +10 padding to left and right
mov dword ptr ds:[edx+0x4C], eax  # combo_display_x = EAX
ret
