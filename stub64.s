
_start:
    call lol

lol:
    ; pre_shellcode
    push rsp
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; shellcode placeholder
    xor rax, rax
    inc rax
    inc rax

    ; post shellcode
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    pop rsp

    ; calculating original entry_point
    pop rbx
    sub rbx, 0x11223344 ; placeholder for fake entry_point
    add rbx, 0x44332211 ; placeholder for legit entry_point
    push rbx
    ret


