
; test shellcode, for it to work, it has to reset the stack state before exiting. Hence the 2 pops at the end.
_start:
    xor rax, rax
    push rax
    inc rax
    mov rdi, rax
    push 0x41414141
    mov rsi, rsp
    mov rdx, 0x8
    syscall
    pop rdx
    pop rdx
