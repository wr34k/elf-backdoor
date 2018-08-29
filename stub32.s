

_start:
    call lol

lol:
    ; pre_shellcode
    push esp
    push eax
    push ebx
    push ecx
    push edx
    push ebp
    push esi
    push edi

    ; shellcode placeholder
    xor eax, eax
    inc eax
    inc eax

    ; post shellcode
    pop edi
    pop esi
    pop ebp
    pop edx
    pop ecx
    pop ebx
    pop eax
    pop esp

    ; calculating original entry_point
    pop ebx
    sub ebx, 0x11223344 ; placeholder for fake entry_point
    add ebx, 0x44332211 ; placeholder for legit entry_point
    push ebx
    ret

