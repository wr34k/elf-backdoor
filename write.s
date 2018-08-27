BITS 64

section .text
    global _start

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
