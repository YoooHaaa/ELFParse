# !/usr/bin/env python3
# -*-coding:utf-8 -*-

"""
# File       ：main.py
# Time       ：2023/5/23
# Author     ：Yooha
"""

from io import TextIOWrapper
import os
from elf32 import Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Sym, Elf32_Dym
from elf64 import Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Sym, Elf64_Dym
from base import Elf_e_ident, Elf_Ehdr, Elf_Shdr, Elf_Phdr, Elf_Sym, Elf_Dym
from typing import List

'''
- 源码路径：/external/llvm/include/llvm/Support/ELF.h
 段名	                内容
.text	                存放编译生成的机器码
.rodata	                存放只读数据，一般是程序中的只读静态变量和字符串常量
.data	                保存已经初始化的全局静态变量和局部静态变量
.bss	                存储未初始化以及初始化为0的全局静态变量和局部静态变量
.rodata1	            也是只读数据段，存放字符串常量，全局 const 变量，该段和 .rodata 类似。
.comment	            存放编译器版本信息，比如 “GCC:GNU4.2.0”
.debug	                调试信息
.dynamic	            动态链接信息，存储各段的信息
.hash	                符号哈希表
.line	                调试时的行号表，即源代码行号与编译后指令的对应表
.note	                额外的编译器信息，比如程序的公司名、发布版本号等
.strtab	                字符串表，用于存储 ELF 文件中用到的各种字符串
.symtab	                符号表，从这里可以找到文件中的各个符号
.shstrtab	            各个段的名称表，实际上是由各个段的名字组成的一个字符串数组
.plt 和 .got	        动态链接的跳转表和全局入口表
.init 和 .fini	        程序初始化和终结代码段
'''

class Elf_header(object):
    def __init__(self, file: TextIOWrapper):
        super(Elf_header, self).__init__()
        self.elf_ehdr: Elf_Ehdr = None
        self.file = file
        self.read_header()

    def read_header(self):
        e_ident = self.init_e_ident()
        self.elf_ehdr.read_Ehdr(self.file, e_ident)


    def init_e_ident(self) -> object:
        e_ident = Elf_e_ident()
        e_ident.read_e_ident(self.file)
        if e_ident.ei_class_2 == 1:    # 32位
            self.elf_ehdr = Elf32_Ehdr()
        elif e_ident.ei_class_2 == 2:  # 64位
            self.elf_ehdr = Elf64_Ehdr()
        else:
            raise ("e_ident -> ei_class_2 数据异常:%d" % (e_ident.ei_class_2))
        return e_ident


# *****************************************************************************************


class ELF(object):
    def __init__(self, path: str):
        super(ELF, self).__init__()
        self.path: str = path
        self.elf_header: Elf_header = None
        self.program_header_table: List[Elf_Phdr] = list()
        self.section_header_table: List[Elf_Shdr] = list()
        self.symbol_table: List[Elf_Sym] = list()
        self.dynamic_table: List[Elf_Dym] = list()
        self.shstrtabs: str = None
        self.strtabs: str = None
        self.dynstrs: str = None

    def read_elf(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, 'rb', True) as files:
            self.read_elf_header(files)
            self.read_program_header_table(files)
            self.get_shstrtab(files)
            self.read_section_header_table(files)
            self.get_strtab(files)
            self.read_symbol_table(files)
            self.get_dynstr(files)
            self.read_dynamic_symbol_table(files)
            self.read_dynamic_table(files)

    def read_elf_header(self, file: TextIOWrapper):
        try:
            self.elf_header = Elf_header(file)
        except Exception as err:
            print(str(err))

    def read_program_header_table(self, file: TextIOWrapper):
        try:
            for i in range(self.elf_header.elf_ehdr.e_phnum):
                if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
                    phdr = Elf32_Phdr()
                elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
                    phdr = Elf64_Phdr()
                else:
                    raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
                file.seek(self.elf_header.elf_ehdr.e_phoff + i * self.elf_header.elf_ehdr.e_phentsize)
                phdr.read_Phdr(file)
                self.program_header_table.append(phdr)
        except Exception as err:
            print(str(err))

    def get_shstrtab(self, file: TextIOWrapper):
        '''
        获取段表字符串表
        '''
        file.seek(self.elf_header.elf_ehdr.e_shoff + self.elf_header.elf_ehdr.e_shtrndx * self.elf_header.elf_ehdr.e_shentsize)
        if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
            shdr = Elf32_Shdr()
        elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
            shdr = Elf64_Shdr()
        else:
            raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
        shdr.read_Shdr(file)
        file.seek(shdr.sh_offset)
        self.shstrtabs = file.read(shdr.sh_size).decode('utf-8')


    def read_section_header_table(self, file: TextIOWrapper):
        try:
            
            for i in range(self.elf_header.elf_ehdr.e_shnum):
                if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
                    shdr = Elf32_Shdr()
                elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
                    shdr = Elf64_Shdr()
                else:
                    raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
                file.seek(self.elf_header.elf_ehdr.e_shoff + i * self.elf_header.elf_ehdr.e_shentsize)
                shdr.read_Shdr(file)
                shdr.read_section_name(self.shstrtabs)
                self.section_header_table.append(shdr)
        except Exception as err:
            print(str(err))

    def get_strtab(self, file: TextIOWrapper):
        '''
        获取字符串表
        '''
        for shdr in self.section_header_table:
            if shdr.section_name.find('.strtab') != -1:
                file.seek(shdr.sh_offset)
                self.strtabs = file.read(shdr.sh_size).decode('utf-8')
                return

    def get_symtab(self) -> Elf_Shdr:
        '''
        获取符号表
        '''
        for symtab in self.section_header_table:
            if symtab.section_name.find('.symtab') != -1:
                return symtab
        return None

    def read_symbol_table(self, file: TextIOWrapper): 
        '''
        .symtab -> symbol_table
        '''
        try:
            shdr = self.get_symtab()
            if shdr:
                idx = shdr.sh_size / shdr.sh_entsize
                for i in range(int(idx)):
                    if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
                        sym = Elf32_Sym()
                    elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
                        sym = Elf64_Sym()
                    else:
                        raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
                    file.seek(shdr.sh_offset + i * shdr.sh_entsize)
                    sym.read_Sym(file)
                    sym.read_sym_name(self.strtabs)
                    self.symbol_table.append(sym)
        except Exception as err:
            print(str(err))

    def get_dynstr(self, file: TextIOWrapper):
        '''
        获取动态字符串表
        '''
        for shdr in self.section_header_table:
            if shdr.section_name.find('.dynstr') != -1:
                file.seek(shdr.sh_offset)
                self.dynstrs = file.read(shdr.sh_size).decode('utf-8')
                return
            
    def get_dynsym(self) -> Elf_Shdr:
        '''
        获取动态符号表
        '''
        for symtab in self.section_header_table:
            if symtab.section_name.find('.dynsym') != -1:
                return symtab
        return None
    
    def read_dynamic_symbol_table(self, file: TextIOWrapper): 
        '''
        .dynsym -> dynamic_symbol_table
        '''
        try:
            shdr = self.get_dynsym()
            if shdr:
                idx = shdr.sh_size / shdr.sh_entsize
                for i in range(int(idx)):
                    if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
                        sym = Elf32_Sym()
                    elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
                        sym = Elf64_Sym()
                    else:
                        raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
                    file.seek(shdr.sh_offset + i * shdr.sh_entsize)
                    sym.read_Sym(file)
                    sym.read_sym_name(self.dynstrs)
                    self.symbol_table.append(sym)
        except Exception as err:
            print(str(err))

    def get_dynamic(self) -> Elf_Shdr:
        '''
        获取动态表
        '''
        for dynamic in self.section_header_table:
            if dynamic.section_name.find('.dynamic') != -1:
                return dynamic
        return None
    
    def read_dynamic_table(self, file: TextIOWrapper):
        '''
        .dynamic -> dynamic_table 此表中保存着各个段的地址，安卓系统通过此表
                                  来确定每个段的地址，而不是通过段表字符串表，
                                  IDA貌似是通过段表字符串表来确定每个段的地址
        '''
        try:
            dynamic = self.get_dynamic()
            if dynamic:
                idx = dynamic.sh_size / dynamic.sh_entsize
                for i in range(int(idx)):
                    if self.elf_header.elf_ehdr.e_ident.ei_class_2 == 1:    # 32位
                        dym = Elf32_Dym()
                    elif self.elf_header.elf_ehdr.e_ident.ei_class_2 == 2:  # 64位
                        dym = Elf64_Dym()
                    else:
                        raise ("e_ident -> ei_class_2 数据异常:%d" % (self.elf_header.elf_ehdr.e_ident.ei_class_2))
                    file.seek(dynamic.sh_offset + i * dynamic.sh_entsize)
                    dym.read_Dym(file)
                    self.dynamic_table.append(dym)
        except Exception as err:
            print(str(err))
# *****************************************************************************************
if __name__ == '__main__':
    file64name = './arm64-v8a/libnative-lib.so'
    file64name2 = './arm64-v8a/libart.so'
    file32name = './armeabi-v7a/libnative-lib.so'
    elf = ELF(file64name2)
    elf.read_elf()



