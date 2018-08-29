#/usr/bin/env python3

from struct import pack, unpack

prettyHex = lambda x: (hex(x) if isinstance(x, int) else ' '.join(hex(i) for i in x))

class ELF(object):
    def __init__(self, elf_file):
        self.elf_file = elf_file

        self.get_header_data()

        self.program_headers = []
        self.section_headers = []

        for off in range(self.e_phoff, (self.e_phoff+(self.e_phnum*self.e_phentsize)), self.e_phentsize):
            self.program_headers += [self.ProgramHeader(self, off)]
        for off in range(self.e_shoff, (self.e_shoff+(self.e_shnum*self.e_shentsize)), self.e_shentsize):
            self.section_headers += [self.SectionHeader(self, off)]


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


    def print_header(self):
        print(f"ELF Magic:          {prettyHex(self.ei_mag)}")
        print(f"ELF Class:          {hex(self.ei_class)}")
        print(f"ELF Data:           {hex(self.ei_data)}")
        print(f"ELF Header Version: {hex(self.ei_version)}")
        print(f"ELF OS/ABI:         {hex(self.ei_osabi)}")
        print(f"ELF Type:           {prettyHex(self.e_type)}")
        print(f"ELF Arch:           {prettyHex(self.e_machine)}")
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

        def print_program_header(self):
            print("="*40)
            print(f"PH Type:        {prettyHex(self.p_type)}")
            print(f"PH Offset:      {prettyHex(self.p_offset)}")
            print(f"PH Virt Addr:   {prettyHex(self.p_vaddr)}")
            print(f"PH Phys Addr:   {prettyHex(self.p_paddr)}")
            print(f"PH File Size:   {prettyHex(self.p_filesz)}")
            print(f"PH Mem Size:    {prettyHex(self.p_memsz)}")
            print(f"PH Flags:       {prettyHex(self.p_flags)}")
            print(f"PH Alignment:   {prettyHex(self.p_align)}")


    class SectionHeader(object):
        def __init__(self, outer, offset):
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

        def print_section_header(self):
            print("="*40)
            print(f"SH Name:        {prettyHex(self.sh_name)}")
            print(f"SH Type:        {prettyHex(self.sh_type)}")
            print(f"SH Flags:       {prettyHex(self.sh_flags)}")
            print(f"SH Addr:        {prettyHex(self.sh_addr)}")
            print(f"SH Offset:      {prettyHex(self.sh_offset)}")
            print(f"SH Size:        {prettyHex(self.sh_size)}")
            print(f"SH Link:        {prettyHex(self.sh_link)}")
            print(f"SH Info:        {prettyHex(self.sh_info)}")
            print(f"SH Addr Align:  {prettyHex(self.sh_addralign)}")
            print(f"SH Entry Size:  {prettyHex(self.sh_entsize)}")

    def build_elf(self):
        elf  =      b""
        elf +=      self.ei_mag
        elf +=      self.p("B", self.ei_class)
        elf +=      self.p("B", self.ei_data)
        elf +=      self.p("B", self.ei_version)
        elf +=      self.p("B", self.ei_osabi)
        elf +=      b"\x00" * 8
        elf +=      self.p("H", self.e_type)
        elf +=      self.p("H", self.e_machine)
        elf +=      self.p("I", self.e_version)
        elf +=      self.p(self.e_entry)
        elf +=      self.p(self.e_phoff)
        elf +=      self.p(self.e_shoff)
        elf +=      self.p("I", self.e_flags)
        elf +=      self.p("H", self.e_ehsize)
        elf +=      self.p("H", self.e_phentsize)
        elf +=      self.p("H", self.e_phnum)
        elf +=      self.p("H", self.e_shentsize)
        elf +=      self.p("H", self.e_shnum)
        elf +=      self.p("H", self.e_shstridx)
        for off in range(len(elf), self.e_phoff):
            elf += b"\x00"

        for ph in self.program_headers:
            elf +=  self.p("I", ph.p_type)
            if self.ei_class == 0x02:
                elf +=  self.p("I", ph.p_flags)
            elf +=  self.p(ph.p_offset)
            elf +=  self.p(ph.p_vaddr)
            elf +=  self.p(ph.p_paddr)
            elf +=  self.p(ph.p_filesz)
            elf +=  self.p(ph.p_memsz)
            if self.ei_class == 0x01:
                elf += self.p("I", ph.p_flags)
            elf +=  self.p(ph.p_align)

        print(prettyHex(len(elf)))
        print(elf)


import sys

with open(sys.argv[1], "rb") as f:
    elf = ELF(f.read())

elf.build_elf()
