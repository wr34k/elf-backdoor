

_start:
    xor rax, rax
    inc rax
    push rax
    push rax
    pop rdi
    pop rdx
    push 0x41414141
    mov rsi, rsp
    add rdx, 3
    syscall
    pop rdx
