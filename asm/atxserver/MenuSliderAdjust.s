.intel_syntax noprefix
mov edx, dword ptr ss:[ebp-0x04]  # EDX = CoreNode ptr from stack
mov ecx, dword ptr ss:[ebp-0x0C]  # ECX = psizl.cx from stack
add ecx, 20                       # Add +10 padding to left and right
mov dword ptr ds:[edx+0x48], ecx  # slider_display_x = ECX
mov ebx, dword ptr ds:[edx+0x4C]  # EBX = textbox_display_width
mov eax, dword ptr ds:[edx+0x1C]  # EAX = display_width
sub eax, ebx                      # 
sub eax, ecx                      # EAX = display_width - slider_display_x - textbox_display_width
mov dword ptr ds:[edx+0x50], eax  # slider_display_width = EAX
mov ebx, dword ptr ds:[edx+0x54]  # 
lea ecx, dword ptr [ebx+ebx+5]    # 
sub eax, ecx                      # EAX = slider_display_widith - (bumper_display_width * 2 + 5)
mov dword ptr ds:[edx+0x58], eax  # slider_actionable_width = EAX
mov eax, dword ptr ds:[edx+0x48]  # EAX = slider_display_x
lea ecx, dword ptr [eax+ebx+3]    # ECX = slider_display_x + bumper_display_width + 3
mov dword ptr ds:[edx+0x5C], ecx  # slider_actionable_x = ECX
ret                               # 
