#!/usr/bin/env python3

from enum import Enum

class ELFHeaderEnum(object):
    class Class(Enum):
        ELF32                   = 0x1
        ELF64                   = 0x2

    class Data(Enum):
        Little_Endian           = 0x1
        Big_Endian              = 0x2

    class Version(Enum):
        ELF                     = 0x1

    class ABI(Enum):
        System_V                = 0x0
        HP_UX                   = 0x1
        NetBSD                  = 0x2
        Linux                   = 0x3
        GNU_Hurd                = 0x4
        Solaris                 = 0x6
        AIX                     = 0x7
        IRIX                    = 0x8
        FreeBSD                 = 0x9
        Tru64                   = 0xa
        Novell_Modesto          = 0xb
        OpenBSD                 = 0xc
        OpenVMS                 = 0xd
        NonStop_Kernel          = 0xe
        AROS                    = 0xf
        Fenix_OS                = 0x10
        CloudABI                = 0x11

    class Type(Enum):
        ET_NONE                 = 0x0
        ET_REL                  = 0x1
        ET_EXEC                 = 0x2
        ET_DYN                  = 0x3
        ET_CORE                 = 0x4
        ET_LOOS                 = 0xfe00
        ET_HIOS                 = 0xfeff
        ET_LOPROC               = 0xff00
        ET_HIPROC               = 0xffff

    class Machine(Enum):
        Unknown                 = 0x0
        SPARC                   = 0x2
        x86                     = 0x3
        MIPS                    = 0x8
        PowerPC                 = 0x14
        S390                    = 0x16
        ARM                     = 0x28
        SuperH                  = 0x2A
        IA_64                   = 0x32
        x86_64                  = 0x3E
        Aarch64                 = 0xB7
        RISC_V                  = 0xF3


class ProgramHeaderEnum(object):
    class Type(Enum):
        PT_NULL                 = 0x0
        PT_LOAD                 = 0x1
        PT_DYNAMIC              = 0x2
        PT_INTERP               = 0x3
        PT_NOTE                 = 0x4
        PT__SHLIB               = 0x5
        PT_PHDR                 = 0x6
        PT_LOOS                 = 0x60000000
        PT_HIOS                 = 0x6fffffff
        PT_LOPROC               = 0x70000000
        PT_HIPROC               = 0x7fffffff

    class Flags(Enum):
        PF_X                    = 0x1
        PF_W                    = 0x2
        PF_R                    = 0x4
        PF_MASKOS               = 0x0ff00000
        PF_NASKPROC             = 0xf0000000


class SectionHeaderEnum(object):
    class Type(Enum):
        SHT_NULL                = 0x0
        SHT_PROGBITS            = 0x1
        SHT_SYMTAB              = 0x2
        SHT_STRTAB              = 0x3
        SHT_RELA                = 0x4
        SHT_HASH                = 0x5
        SHT_DYNAMIC             = 0x6
        SHT_NOTE                = 0x7
        SHT_NOBITS              = 0x8
        SHT_REL                 = 0x9
        SHT_SHLIB               = 0xa
        SHT_DYNSYM              = 0xb
        SHT_INIT_ARRAY          = 0xe
        SHT_FINI_ARRAY          = 0xf
        SHT_PREINIT_ARRAY       = 0x10
        SHT_GROUP               = 0x11
        SHT_SYMTAB_SHNDX        = 0x12
        SHT_NUM                 = 0x13
        SHT_LOOS                = 0x60000000

    class Flags(Enum):
        SHF_WRITE               = 0x1
        SHF_ALLOC               = 0x2
        SHF_EXECINSTR           = 0x4
        SHF_MERGE               = 0x10
        SHF_STRINGS             = 0x20
        SHF_INFO_LINK           = 0x40
        SHF_LINK_ORDER          = 0x80
        SHF_OS_NONCONFIRMING    = 0x100
        SHF_GROUP               = 0x200
        SHF_TLS                 = 0x400
        SHF_MASKOS              = 0x0ff00000
        SHF_MASKPROC            = 0xf0000000
        SHF_ORDERED             = 0x40000000
        SHF_EXCLUDE             = 0x80000000
