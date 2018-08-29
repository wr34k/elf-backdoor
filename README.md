# ELF BACKDOOR

Backdoor any ELF file by putting a shellcode in a codecave, and setting the entry_point to it.


For now, it works well with x86_64, but doesn't with x86 binaries. I still have to debug to understand why. Also, the backdoored binary might be a bit broken cause ldd doesn't find any shared libs. Gotta find out why too.

TODO:
* Be able to trigger shellcode from anywhere in the code
    * For this to work, script has to change the desired code to a jmp to the codecave, and append the legit code replaced to the end of the shellcode.
