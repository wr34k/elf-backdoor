# ELF BACKDOOR

Backdoor any ELF file by putting a shellcode in a codecave, and setting the entry_point to it.
Now with coloured output!


TODO:
* Be able to trigger shellcode from anywhere in the code
    * For this to work, script has to change the desired code to a jmp to the codecave, and append the legit code replaced to the end of the shellcode.
