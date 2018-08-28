# ELF BACKDOOR

Backdoor any x86_64 ELF executable by putting a shellcode in a codecave, and setting the entry_point to it.

For now, it only do that.

TODO:
* Support x86 ELF executables
* Support ELF shared object
* Be able to trigger shellcode from anywhere in the code
    * For this to work, script has to change the desired code to a jmp to the codecave, and append the legit code replaced to the end of the shellcode.
