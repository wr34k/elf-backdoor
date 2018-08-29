BITS 32

_start:
    xor eax, eax
    inc eax
    push eax
    pop ebx
    add eax, 3
    push eax
    pop edx
    push 0x41414141
    mov ecx, esp
    int 0x80
    pop edx
