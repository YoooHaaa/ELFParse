# !/usr/bin/env python3
# -*-coding:utf-8 -*-

"""
# File       : main.py
# Time       ：2023/5/23
# Author     ：Yooha
"""

import struct
from io import TextIOWrapper
from base import Elf_Ehdr, Elf_Phdr, Elf_Shdr, Elf_Sym, Elf_Dym


class Elf64_Ehdr(Elf_Ehdr):
    def __init__(self):
        Elf_Ehdr.__init__(self)

    def read_e_entry(self, file: TextIOWrapper):
        self.e_entry = struct.unpack('Q', file.read(8))[0]
        print("read e_entry = 0x%x" % (self.e_entry))

    def read_e_phoff(self, file: TextIOWrapper):
        self.e_phoff = struct.unpack('Q', file.read(8))[0]
        print("read e_phoff = %d" % (self.e_phoff))

    def read_e_shoff(self, file: TextIOWrapper):
        self.e_shoff = struct.unpack('Q', file.read(8))[0]
        print("read e_shoff = %d" % (self.e_shoff))


class Elf64_Phdr(Elf_Phdr):
    def __init__(self):
        Elf_Phdr.__init__(self)

    def read_Phdr(self, file: TextIOWrapper): 
        self.read_p_type(file)
        self.read_p_flags(file)
        self.read_p_offset(file)
        self.read_p_vaddr(file)
        self.read_p_paddr(file)
        self.read_p_filesz(file)
        self.read_p_memsz(file)
        self.read_p_align(file)
        print('\n')

    def read_p_offset(self, file: TextIOWrapper):
        self.p_offset = struct.unpack('Q', file.read(8))[0]
        print("read p_offset = 0x%x" % (self.p_offset))

    def read_p_vaddr(self, file: TextIOWrapper):
        self.p_vaddr = struct.unpack('Q', file.read(8))[0]
        print("read p_vaddr = 0x%x" % (self.p_vaddr))

    def read_p_paddr(self, file: TextIOWrapper):
        self.p_paddr = struct.unpack('Q', file.read(8))[0]
        print("read p_paddr = 0x%x" % (self.p_paddr))

    def read_p_filesz(self, file: TextIOWrapper):
        self.p_filesz = struct.unpack('Q', file.read(8))[0]
        print("read p_filesz = %d" % (self.p_filesz))

    def read_p_memsz(self, file: TextIOWrapper):
        self.p_memsz = struct.unpack('Q', file.read(8))[0]
        print("read p_memsz = %d" % (self.p_memsz))

    def read_p_align(self, file: TextIOWrapper):
        self.p_align = struct.unpack('Q', file.read(8))[0]
        print("read p_align = %d" % (self.p_align))


class Elf64_Shdr(Elf_Shdr):
    def __init__(self):
        Elf_Shdr.__init__(self)

    def read_sh_flags(self, file: TextIOWrapper):
        self.sh_flags = struct.unpack('Q', file.read(8))[0]
        print("read sh_flags = %d" % (self.sh_flags))

    def read_sh_addr(self, file: TextIOWrapper):
        self.sh_addr = struct.unpack('Q', file.read(8))[0]
        print("read sh_addr = 0x%x" % (self.sh_addr))

    def read_sh_offset(self, file: TextIOWrapper):
        self.sh_offset = struct.unpack('Q', file.read(8))[0]
        print("read sh_offset = 0x%x" % (self.sh_offset))

    def read_sh_size(self, file: TextIOWrapper):
        self.sh_size = struct.unpack('Q', file.read(8))[0]
        print("read sh_size = %d" % (self.sh_size))

    def read_sh_addralign(self, file: TextIOWrapper):
        self.sh_addralign = struct.unpack('Q', file.read(8))[0]
        print("read sh_addralign = %d" % (self.sh_addralign))

    def read_sh_entsize(self, file: TextIOWrapper):
        self.sh_entsize = struct.unpack('Q', file.read(8))[0]
        print("read sh_entsize = %d" % (self.sh_entsize))


class Elf64_Sym(Elf_Sym):
    def __init__(self):
        Elf_Sym.__init__(self)

    def read_Sym(self, file: TextIOWrapper):
        self.read_st_name(file)
        self.read_st_info(file)
        self.read_st_other(file)
        self.read_st_shndx(file)
        self.read_st_value(file)
        self.read_st_size(file)


    def read_st_value(self, file: TextIOWrapper):
        self.st_value = struct.unpack('Q', file.read(8))[0]
        print("read st_value = %d" % (self.st_value))

    def read_st_size(self, file: TextIOWrapper):
        self.st_size = struct.unpack('Q', file.read(8))[0]
        print("read st_size = %d" % (self.st_size))


class Elf64_Dym(Elf_Dym):
    def __init__(self):
        Elf_Dym.__init__(self)


    def read_d_tag(self, file: TextIOWrapper):
        self.d_tag = struct.unpack('q', file.read(8))[0]
        keys = Elf_Dym.TAG.keys()
        for key in keys:
            if self.d_tag == Elf_Dym.TAG[key]:
                print('read d_tag = 0x%-10X  type = %s' % (self.d_tag, key))
                return
            
    def read_d_un(self, file: TextIOWrapper):
        self.d_un = struct.unpack('Q', file.read(8))[0]
        print("read d_un = 0x%x\n" % (self.d_un))




