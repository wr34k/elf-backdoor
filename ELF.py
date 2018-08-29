#/usr/bin/env python3

from struct import pack, unpack
from ELFEnum import *

prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))



class ELF(object):
    def __init__(self, elf_file):
        self.elf_file = bytearray(elf_file)
        self.get_header_data()
        self.program_headers = []
        self.section_headers = []

        idx = 0
        for off in range(self.e_phoff, (self.e_phoff+(self.e_phnum*self.e_phentsize)), self.e_phentsize):
            ph = self.ProgramHeader(self, off)
            ph.idx = idx
            idx += 1
            self.program_headers += [ph]

        idx = 0
        for off in range(self.e_shoff, (self.e_shoff+(self.e_shnum*self.e_shentsize)), self.e_shentsize):
            sh = self.SectionHeader(self, off)
            sh.idx = idx
            idx += 1
            self.section_headers += [sh]

        self.get_section_names()


    def get_header_data(self):
        self.ei_mag         = self.elf_file[0x00:0x04]
        self.ei_class       = self.elf_file[0x04]
        self.ei_data        = self.elf_file[0x05]
        self.ei_version     = self.elf_file[0x06]
        self.ei_osabi       = self.elf_file[0x07]

        bo = '<' if self.ei_data == 0x01 else '>'
        fo = 'I' if self.ei_class == 0x01 else 'Q'
        self.up = lambda x,y=None: (unpack(f"{bo}{x}", y)[0] if y is not None else unpack(f"{bo}{fo}", x)[0])
        self.p = lambda x,y=None: (pack(f"{bo}{x}", y) if y is not None else pack(f"{bo}{fo}", x))
        self.h_size = 0x04 if self.ei_class == 0x1 else 0x08

        self.e_type         = self.up("H", self.elf_file[0x10:0x12])
        self.e_machine      = self.up("H", self.elf_file[0x12:0x14])
        self.e_version      = self.up("I", self.elf_file[0x14:0x18])
        offset = 0x18+self.h_size
        self.e_entry        = self.up(self.elf_file[0x18:offset])
        self.e_phoff        = self.up(self.elf_file[offset:offset+self.h_size])
        offset += self.h_size
        self.e_shoff        = self.up(self.elf_file[offset:offset+self.h_size])
        offset += self.h_size
        self.e_flags        = self.up("I", self.elf_file[offset:offset+0x04])
        offset += 0x04
        self.e_ehsize       = self.up("H", self.elf_file[offset:offset+0x02])
        offset += 0x02
        self.e_phentsize    = self.up("H", self.elf_file[offset:offset+0x02])
        offset += 0x02
        self.e_phnum        = self.up("H", self.elf_file[offset:offset+0x02])
        offset += 0x02
        self.e_shentsize    = self.up("H", self.elf_file[offset:offset+0x02])
        offset += 0x02
        self.e_shnum        = self.up("H", self.elf_file[offset:offset+0x02])
        offset += 0x02
        self.e_shstridx     = self.up("H", self.elf_file[offset:offset+0x02])

    def get_section_names(self):
        for sh in self.section_headers:
            if sh.idx == self.e_shstridx:
                names = self.elf_file[sh.sh_offset:sh.sh_offset+sh.sh_size]

        for i in range(len(self.section_headers)):
            self.section_headers[i].sh_name_str = readString(names[self.section_headers[i].sh_name:])

    def print_header(self):
        print(f"ELF Magic:          {prettyHex(self.ei_mag)}")
        print(f"ELF Class:          {ELFHeaderEnum.Class(self.ei_class).name}")
        print(f"ELF Data:           {ELFHeaderEnum.Data(self.ei_data).name}")
        print(f"ELF Header Version: {ELFHeaderEnum.Version(self.ei_version).name}")
        print(f"ELF OS/ABI:         {ELFHeaderEnum.ABI(self.ei_osabi).name}")
        print(f"ELF Type:           {ELFHeaderEnum.Type(self.e_type).name}")
        print(f"ELF Arch:           {ELFHeaderEnum.Machine(self.e_machine).name}")
        print(f"ELF Version:        {prettyHex(self.e_version)}")
        print(f"ELF Entry Point:    {prettyHex(self.e_entry)}")
        print(f"ELF Start PH:       {prettyHex(self.e_phoff)}")
        print(f"ELF Start SH:       {prettyHex(self.e_shoff)}")
        print(f"ELF Flags:          {prettyHex(self.e_flags)}")
        print(f"ELF Header Size:    {prettyHex(self.e_ehsize)}")
        print(f"ELF PH Size:        {prettyHex(self.e_phentsize)}")
        print(f"ELF PH Number:      {prettyHex(self.e_phnum)}")
        print(f"ELF SH Size:        {prettyHex(self.e_shentsize)}")
        print(f"ELF SH Number:      {prettyHex(self.e_shnum)}")
        print(f"ELF SH Str Index:   {prettyHex(self.e_shstridx)}")


    class ProgramHeader(object):
        def __init__(self, outer, offset):
            self.idx        = None
            self.off_start  = offset

            self.p_type     = outer.up("I", outer.elf_file[offset:offset+0x04])
            offset += 0x04
            if outer.ei_class == 0x02:
                self.p_flags = outer.up("I", outer.elf_file[offset:offset+0x04])
                offset += 0x04
            self.p_offset   = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.p_vaddr    = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.p_paddr    = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.p_filesz   = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.p_memsz    = outer.up(outer.elf_file[offset:offset+outer.h_size])
            if outer.ei_class == 0x01:
                self.p_flags = outer.up("I", outer.elf_file[offset:0x04])
                offset += 0x04
            self.p_align    = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += self.h_size

            self.off_end    = offset
            self.raw = outer.elf_file[self.off_start:self.off_end]

        def print_program_header(self):
            print("="*40)
            print(f"PH Type:        {ProgramHeaderEnum.Type(self.p_type).name}")
            print(f"PH Offset:      {prettyHex(self.p_offset)}")
            print(f"PH Virt Addr:   {prettyHex(self.p_vaddr)}")
            print(f"PH Phys Addr:   {prettyHex(self.p_paddr)}")
            print(f"PH File Size:   {prettyHex(self.p_filesz)}")
            print(f"PH Mem Size:    {prettyHex(self.p_memsz)}")
            print(f"PH Flags:       {prettyHex(self.p_flags)}")
            print(f"PH Alignment:   {prettyHex(self.p_align)}")


    class SectionHeader(object):
        def __init__(self, outer, offset):
            self.idx            = None
            self.off_start = offset

            self.sh_name        = outer.up("I", outer.elf_file[offset:offset+0x04])
            offset += 0x04
            self.sh_type        = outer.up("I", outer.elf_file[offset:offset+0x04])
            offset += 0x04
            self.sh_flags       = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.sh_addr        = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.sh_offset      = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.sh_size        = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.sh_link        = outer.up("I", outer.elf_file[offset:offset+0x04])
            offset += 0x04
            self.sh_info        = outer.up("I", outer.elf_file[offset:offset+0x04])
            offset += 0x04
            self.sh_addralign   = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size
            self.sh_entsize     = outer.up(outer.elf_file[offset:offset+outer.h_size])
            offset += outer.h_size

            self.off_end = offset
            self.raw = outer.elf_file[off_start:off_end]

        def prettyFlags(self):
            flags = []
            for flag in SectionHeaderEnum.Flags:
                if flag.value & self.sh_flags:
                    flags += [flag.name]
            return ' | '.join(flags)

        def print_section_header(self):
            print("="*40)
            print(f"SH Name:        {self.sh_name_str}")
            print(f"SH Type:        {SectionHeaderEnum.Type(self.sh_type).name}")
            print(f"SH Flags:       {self.prettyFlags()}")
            print(f"SH Addr:        {prettyHex(self.sh_addr)}")
            print(f"SH Offset:      {prettyHex(self.sh_offset)}")
            print(f"SH Size:        {prettyHex(self.sh_size)}")
            print(f"SH Link:        {prettyHex(self.sh_link)}")
            print(f"SH Info:        {prettyHex(self.sh_info)}")
            print(f"SH Addr Align:  {prettyHex(self.sh_addralign)}")
            print(f"SH Entry Size:  {prettyHex(self.sh_entsize)}")

    def get_section_from_offset(self, offset):
        for sh in self.section_headers:
            if offset in range(sh.sh_offset, sh.sh_offset+sh.sh_size):
                return sh
        return None

    def build_elf(self):
        elf = bytearray(len(self.elf_file))
        off =    0x00

        ## HEADER
        elf[off:+0x04] = self.ei_mag
        off +=   0x04
        elf[off] = self.ei_class
        off +=   0x01
        elf[off] = self.ei_data
        off +=   0x01
        elf[off] = self.ei_version
        off +=   0x01
        elf[off] = self.ei_osabi
        off +=   0x01
        elf[off:off+0x08] = b"\x00" * 8
        off +=   0x08
        elf[off:off+0x02] = self.p("H", self.e_type)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_machine)
        off += 0x02
        elf[off:off+0x04] = self.p("I", self.e_version)
        off += 0x04
        elf[off:off+self.h_size] = self.p(self.e_entry)
        off += self.h_size
        elf[off:off+self.h_size] = self.p(self.e_phoff)
        off += self.h_size
        elf[off:off+self.h_size] = self.p(self.e_shoff)
        off += self.h_size
        elf[off:off+0x04] = self.p("I", self.e_flags)
        off += 0x04
        elf[off:off+0x02] = self.p("H", self.e_ehsize)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_phentsize)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_phnum)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_shentsize)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_shnum)
        off += 0x02
        elf[off:off+0x02] = self.p("H", self.e_shstridx)
        off += 0x02


        # Program headers table
        off = self.e_phoff
        for ph in self.program_headers:
            elf[off:off+0x04] = self.p("I", ph.p_type)
            off += 0x04
            if self.ei_class == 0x02:
                elf[off:off+0x04] = self.p("I", ph.p_flags)
                off += 0x04
            elf[off:off+self.h_size] = self.p(ph.p_offset)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(ph.p_vaddr)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(ph.p_paddr)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(ph.p_filesz)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(ph.p_memsz)
            off += self.h_size
            if self.ei_class == 0x01:
                elf[off:off+0x04] = self.p("I", ph.p_flags)
                off += 0x04
            elf[off:off+self.h_size] = self.p(ph.p_align)
            off += self.h_size

        # Section headers table
        off = self.e_shoff
        for sh in self.section_headers:
            elf[off:off+0x04] = self.p("I", sh.sh_name)
            off += 0x04
            elf[off:off+0x04] = self.p("I", sh.sh_type)
            off += 0x04
            elf[off:off+self.h_size] = self.p(sh.sh_flags)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(sh.sh_addr)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(sh.sh_offset)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(sh.sh_size)
            off += self.h_size
            elf[off:off+0x04] = self.p("I", sh.sh_link)
            off += 0x04
            elf[off:off+0x04] = self.p("I", sh.sh_info)
            off += 0x04
            elf[off:off+self.h_size] = self.p(sh.sh_addralign)
            off += self.h_size
            elf[off:off+self.h_size] = self.p(sh.sh_entsize)
            off += self.h_size

            # filling section
            elf[sh.sh_offset:sh.sh_offset+sh.sh_size] = self.elf_file[sh.sh_offset:sh.sh_offset+sh.sh_size]

        return elf


def readString(bytestr):
    string = b""
    for i in range(len(bytestr)):
        if bytestr[i] == 0x00:
            return str(string, 'utf-8', 'ignore')
        string += bytes([bytestr[i]])
