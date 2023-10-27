# !/usr/bin/env python3
# -*-coding:utf-8 -*-

"""
# File       : main.py
# Time       ：2023/5/23
# Author     ：Yooha
"""

import abc
from io import TextIOWrapper
import struct


class Elf_e_ident(object):
    def __init__(self):
        super(Elf_e_ident, self).__init__()
        self.file_identification = None    # Magic 前4个字节固定是 7F 45 4C 46; 45 4C 46 是ELF的ascii码；
        self.ei_class_2 = None             # Class 01为32位，02为64位
        self.ei_data = None                # Data  01 是小端序， 02 是大端序
        self.ei_version = None             # Version 表示ELF的版本号，不过一般都为1，因为ELF1.2版本后到目前都没有更新
        self.ei_osabi = None               # OS/ABI 表示使用的ABI类型，不过一般情况下是0， 也就是UNIX - System V
        self.ei_abiversion = None          # ABI VERSION 表示使用的ABI的版本，一般情况下是0
        self.ei_pad = None                 #
        self.ei_nident_SIZE = None         #


    def read_e_ident(self, file: TextIOWrapper):
        self.read_magic(file)
        self.read_class(file)
        self.read_data(file)
        self.read_version(file)
        self.read_osabi(file)
        self.read_abiversion(file)
        self.read_pad(file)
        self.read_nident_SIZE(file)

    def read_magic(self, file: TextIOWrapper):
        self.file_identification = []
        for i in range(4):
            self.file_identification.append(
                file.read(1).decode(encoding='utf-8'))
        print("read Magic = " + str(self.file_identification))

    def read_class(self, file: TextIOWrapper):
        self.ei_class_2 = struct.unpack('B', file.read(1))[0]
        print("read Class = " + str(self.ei_class_2))

    def read_data(self, file: TextIOWrapper):
        self.ei_data = struct.unpack('B', file.read(1))[0]
        print("read Data = " + str(self.ei_data))

    def read_version(self, file: TextIOWrapper):
        self.ei_version = struct.unpack('B', file.read(1))[0]
        print("read Version = " + str(self.ei_version))

    def read_osabi(self, file: TextIOWrapper):
        self.ei_osabi = struct.unpack('B', file.read(1))[0]
        print("read OS/ABI = " + str(self.ei_osabi))

    def read_abiversion(self, file: TextIOWrapper):
        self.ei_abiversion = struct.unpack('B', file.read(1))[0]
        print("read ABI VERSION = " + str(self.ei_abiversion))

    def read_pad(self, file: TextIOWrapper):
        self.ei_pad = []
        for i in range(6):
            self.ei_pad.append(struct.unpack('B', file.read(1))[0])
        print("read pad = " + str(self.ei_pad))

    def read_nident_SIZE(self, file: TextIOWrapper):
        self.ei_nident_SIZE = struct.unpack('B', file.read(1))[0]
        print("read nident SIZE = " + str(self.ei_nident_SIZE))


class Elf_Ehdr(metaclass=abc.ABCMeta):
    '''
    ELF头
    '''

    def __init__(self):
        self.e_ident:Elf_e_ident = None       # Magic number and other info
        self.e_type = None        # 表示ELF的文件类型，ET_REL(1)为可重定位文件，一般是.o文件；ET_EXEC(2)为可执行文件；ET_DYN(3)一般为.so文件; ET_CORE(4) 为core file，也就是core dump 产生的文件
        self.e_machine = None     # 常量定义也在elf.h中，数量得有点多，其中EM_x86_64 为62
        self.e_version = None     # 意义和上面的Version一致
        self.e_entry = None       # 表示程序执行的入口地址
        self.e_phoff = None       # 表示Program Header的入口偏移量
        self.e_shoff = None       # 表示Section Header的入口偏移量
        self.e_flags = None       # 表示ELF文件相关的特定处理器的flag
        self.e_ehsize = None      # 表示ELF Header大小, 当前header的大小就是64 字节
        self.e_phentsize = None   # 表示Program Header的大小
        self.e_phnum = None       # 表示Program Header的个数
        self.e_shentsize = None   # 表示Section Header的大小
        self.e_shnum = None       # 表示Section Header的个数
        self.e_shtrndx = None     # 段表字符串表所在段在段表中的下标


    def read_Ehdr(self, file: TextIOWrapper, e_ident: object):
        self.read_e_ident(e_ident)
        self.read_e_type(file)
        self.read_e_machine(file)
        self.read_e_version(file)
        self.read_e_entry(file)
        self.read_e_phoff(file)
        self.read_e_shoff(file)
        self.read_e_flags(file)
        self.read_e_ehsize(file)
        self.read_e_phentsize(file)
        self.read_e_phnum(file)
        self.read_e_shentsize(file)
        self.read_e_shnum(file)
        self.read_e_shtrndx(file)


    def read_e_ident(self, e_ident: object):
        self.e_ident = e_ident

    def read_e_type(self, file: TextIOWrapper):
        self.e_type = struct.unpack('H', file.read(2))[0]
        print("read e_type = " + str(self.e_type))

    def read_e_machine(self, file: TextIOWrapper):
        self.e_machine = struct.unpack('H', file.read(2))[0]
        print("read e_machine = " + str(self.e_machine))

    def read_e_version(self, file: TextIOWrapper):
        self.e_version = struct.unpack('I', file.read(4))[0]
        print("read e_version = " + str(self.e_version))

    @abc.abstractmethod
    def read_e_entry(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_e_phoff(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_e_shoff(self, file: TextIOWrapper):
        pass

    def read_e_flags(self, file: TextIOWrapper):
        self.e_flags = struct.unpack('I', file.read(4))[0]
        print("read e_flags = %d" % (self.e_flags))

    def read_e_ehsize(self, file: TextIOWrapper):
        self.e_ehsize = struct.unpack('H', file.read(2))[0]
        print("read e_ehsize = %d" % (self.e_ehsize))

    def read_e_phentsize(self, file: TextIOWrapper):
        self.e_phentsize = struct.unpack('H', file.read(2))[0]
        print("read e_phentsize = %d" % (self.e_phentsize))

    def read_e_phnum(self, file: TextIOWrapper):
        self.e_phnum = struct.unpack('H', file.read(2))[0]
        print("read e_phnum = %d" % (self.e_phnum))

    def read_e_shentsize(self, file: TextIOWrapper):
        self.e_shentsize = struct.unpack('H', file.read(2))[0]
        print("read e_shentsize = %d" % (self.e_shentsize))

    def read_e_shnum(self, file: TextIOWrapper):
        self.e_shnum = struct.unpack('H', file.read(2))[0]
        print("read e_shnum = %d" % (self.e_shnum))

    def read_e_shtrndx(self, file: TextIOWrapper):
        self.e_shtrndx = struct.unpack('H', file.read(2))[0]
        print("read e_shtrndx = %d" % (self.e_shtrndx))


class Elf_Phdr(metaclass=abc.ABCMeta):
    '''
    段表
    '''
    def __init__(self):
        self.p_type = None    # 段类型
        self.p_flags = None   # 段标志
        self.p_offset = None  # 段所在的文件偏移量，单位为字节
        self.p_vaddr = None   # 段起始的虚拟地址
        self.p_paddr = None   # 段开始的物理地址(特定于操作系统)
        self.p_filesz = None  # 文件映像的字节数(可能为零)
        self.p_memsz = None   # 内存映像中的字节数(可能为零)
        self.p_align = None   # 段对齐约束


    @abc.abstractmethod
    def read_Phdr(self, file: TextIOWrapper): # 32位与64位的排列顺序不同
        pass

    def read_p_type(self, file: TextIOWrapper):
        self.p_type = struct.unpack('I', file.read(4))[0]
        print("read p_type = %d" % (self.p_type))

    def read_p_flags(self, file: TextIOWrapper):
        self.p_flags = struct.unpack('I', file.read(4))[0]
        print("read p_flags = %d" % (self.p_flags))

    @abc.abstractmethod
    def read_p_offset(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_p_vaddr(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_p_paddr(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_p_filesz(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_p_memsz(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_p_align(self, file: TextIOWrapper):
        pass



class Elf_Shdr(metaclass=abc.ABCMeta):

    def __init__(self):
        self.sh_name = None     # 节区名称,此处是一个在名称节区的地址偏移（字符串的起点偏移）
        self.section_name = None
        self.sh_type = None     # 节区类型，决定节表的作用
        self.sh_flags = None    # 同Program Header的p_flags，表示读写执行权限
        self.sh_addr = None     # 节区索引地址
        self.sh_offset = None   # 节区相对于文件的偏移地址  //修改rodata的此值，能让IDA的字符串乱掉
        self.sh_size = None     # 节区的大小
        self.sh_link = None     # 此成员给出节区头部表索引链接
        self.sh_info = None     # 此成员给出附加信息
        self.sh_addralign = None# 某些节区带有地址对齐约束。例如,如果一个节区保存一个doubleword,那么系统必须保证整个节区能够按双字对齐。sh_addr 对sh_addralign 取模,结果必须为 0。目前仅允许取值为 0 和 2的幂次数。数值 0 和 1 表示节区没有对齐约束。
        self.sh_entsize = None  # 某些节区中包含固定大小的项目,如符号表。对于这类节区,此成员给出每个表项的长度字节数。 如果节区中并不包含固定长度表项的表格,此成员取值为 0
        

    def read_Shdr(self, file: TextIOWrapper): 
        self.read_sh_name(file)
        self.read_sh_type(file)
        self.read_sh_flags(file)
        self.read_sh_addr(file)
        self.read_sh_offset(file)
        self.read_sh_size(file)
        self.read_sh_link(file)
        self.read_sh_info(file)
        self.read_sh_addralign(file)
        self.read_sh_entsize(file)


    def read_sh_name(self, file: TextIOWrapper):
        self.sh_name = struct.unpack('I', file.read(4))[0]
        print("read sh_name = %d" % (self.sh_name))

    def read_section_name(self, shstrtabs: str):
        idx = shstrtabs.find('\0', self.sh_name)
        self.section_name = shstrtabs[self.sh_name:idx]
        print("read section_name = %s\n" % (self.section_name))

    def read_sh_type(self, file: TextIOWrapper):
        self.sh_type = struct.unpack('I', file.read(4))[0]
        print("read sh_type = %d" % (self.sh_type))

    @abc.abstractmethod
    def read_sh_flags(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_sh_addr(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_sh_offset(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_sh_size(self, file: TextIOWrapper):
        pass

    def read_sh_link(self, file: TextIOWrapper):
        self.sh_link = struct.unpack('I', file.read(4))[0]
        print("read sh_link = %d" % (self.sh_link))

    def read_sh_info(self, file: TextIOWrapper):
        self.sh_info = struct.unpack('I', file.read(4))[0]
        print("read sh_info = %d" % (self.sh_info))

    @abc.abstractmethod
    def read_sh_addralign(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_sh_entsize(self, file: TextIOWrapper):
        pass


class Elf_Sym(metaclass=abc.ABCMeta):

    def __init__(self):
        self.st_name = None     # 符号名字在字符串表中的偏移
        self.st_value = None    # 符号相应的值，可能是地址或一个绝对值数
        self.st_size = None     # 符号大小
        self.st_info = None     # 符号类型和绑定值
        self.st_other = None    # 默认0
        self.st_shndx = None    # 符号所在的段
        self.sym_name = None
   
    @abc.abstractmethod
    def read_Sym(self, file: TextIOWrapper): 
        pass

    def read_sym_name(self, strtabs:str):
        idx = strtabs.find('\0', self.st_name)
        self.section_name = strtabs[self.st_name:idx]
        print("read sym_name = %s\n" % (self.section_name))

    def read_st_name(self, file: TextIOWrapper):
        self.st_name = struct.unpack('I', file.read(4))[0]
        print("read st_name = %x" % (self.st_name))

    @abc.abstractmethod
    def read_st_value(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_st_size(self, file: TextIOWrapper):
        pass


    def read_st_info(self, file: TextIOWrapper):
        self.st_info = struct.unpack('B', file.read(1))[0]
        print("read st_info = " + str(self.st_info))

    def read_st_other(self, file: TextIOWrapper):
        self.st_other = struct.unpack('B', file.read(1))[0]
        print("read st_other = " + str(self.st_other))

    def read_st_shndx(self, file: TextIOWrapper):
        self.st_shndx = struct.unpack('H', file.read(2))[0]
        print("read st_shndx = " + str(self.st_shndx))


class Elf_Dym(metaclass=abc.ABCMeta):
    '''
    动态 .dynamic 节
    '''
    TAG = {
        "DT_NULL":0,
        "DT_NEEDED":1,
        "DT_PLTRELSZ":2,
        "DT_PLTGOT":3,
        "DT_HASH":4,
        "DT_STRTAB":5,  #指向.dynstr段，而不是strtab或shstrtab
        "DT_SYMTAB":6,
        "DT_RELA":7,
        "DT_RELASZ":8,
        "DT_RELAENT":9,
        "DT_STRSZ":10,
        "DT_SYMENT":11,
        "DT_INIT":12,
        "DT_FINI":13,
        "DT_SONAME":14,
        "DT_RPATH":15,
        "DT_SYMBOLIC":16,
        "DT_REL":17,
        "DT_RELSZ":18,
        "DT_RELENT":19,
        "DT_PLTREL":20,
        "DT_DEBUG":21,
        "DT_TEXTREL":22,
        "DT_JMPREL":23,
        "DT_BIND_NOW":24,
        "DT_INIT_ARRAY":25,
        "DT_FINI_ARRAY":26,
        "DT_INIT_ARRAYSZ":27,
        "DT_FINI_ARRAYSZ":28,
        "DT_RUNPATH":29,
        "DT_FLAGS":30,
        "DT_ENCODING":32,
        "DT_PREINIT_ARRAY":32,
        "DT_PREINIT_ARRAYSZ":33,
        "DT_LOOS":0x60000000,
        "DT_HIOS":0x6FFFFFFF,
        "DT_LOPROC":0x70000000,
        "DT_HIPROC":0x7FFFFFFF,
        "DT_GNU_HASH":0x6FFFFEF5,
        "DT_TLSDESC_PLT":0x6FFFFEF6,
        "DT_TLSDESC_GOT":0x6FFFFEF7,
        "DT_RELACOUNT":0x6FFFFFF9,
        "DT_RELCOUNT":0x6FFFFFFA,
        "DT_FLAGS_1":0X6FFFFFFB,
        "DT_VERSYM":0x6FFFFFF0,
        "DT_VERDEF":0X6FFFFFFC,
        "DT_VERDEFNUM":0X6FFFFFFD,
        "DT_VERNEED":0X6FFFFFFE,
        "DT_VERNEEDNUM":0X6FFFFFFF,
        "DT_MIPS_RLD_VERSION":0x70000001,
        "DT_MIPS_TIME_STAMP":0x70000002,
        "DT_MIPS_ICHECKSUM":0x70000003,
        "DT_MIPS_IVERSION":0x70000004,
        "DT_MIPS_FLAGS":0x70000005,
        "DT_MIPS_BASE_ADDRESS":0x70000006,
        "DT_MIPS_MSYM":0x70000007,
        "DT_MIPS_CONFLICT":0x70000008,
        "DT_MIPS_LIBLIST":0x70000009,
        "DT_MIPS_LOCAL_GOTNO":0x7000000a,
        "DT_MIPS_CONFLICTNO":0x7000000b,
        "DT_MIPS_LIBLISTNO":0x70000010,
        "DT_MIPS_SYMTABNO":0x70000011,
        "DT_MIPS_UNREFEXTNO":0x70000012,
        "DT_MIPS_GOTSYM":0x70000013,
        "DT_MIPS_HIPAGENO":0x70000014,
        "DT_MIPS_RLD_MAP":0x70000016,
        "DT_MIPS_DELTA_CLASS":0x70000017,
        "DT_MIPS_DELTA_CLASS_NO":0x70000018,
        "DT_MIPS_DELTA_INSTANCE":0x70000019,
        "DT_MIPS_DELTA_INSTANCE_NO":0x7000001A,
        "DT_MIPS_DELTA_RELOC":0x7000001B,
        "DT_MIPS_DELTA_RELOC_NO":0x7000001C,
        "DT_MIPS_DELTA_SYM":0x7000001D,
        "DT_MIPS_DELTA_SYM_NO":0x7000001E,
        "DT_MIPS_DELTA_CLASSSYM":0x70000020,
        "DT_MIPS_DELTA_CLASSSYM_NO":0x70000021,
        "DT_MIPS_CXX_FLAGS":0x70000022,
        "DT_MIPS_PIXIE_INIT":0x70000023,
        "DT_MIPS_SYMBOL_LIB":0x70000024,
        "DT_MIPS_LOCALPAGE_GOTIDX":0x70000025,
        "DT_MIPS_LOCAL_GOTIDX":0x70000026,
        "DT_MIPS_HIDDEN_GOTIDX":0x70000027,
        "DT_MIPS_PROTECTED_GOTIDX":0x70000028,
        "DT_MIPS_OPTIONS":0x70000029,
        "DT_MIPS_INTERFACE":0x7000002A,
        "DT_MIPS_DYNSTR_ALIGN":0x7000002B,
        "DT_MIPS_INTERFACE_SIZE":0x7000002C,
        "DT_MIPS_RLD_TEXT_RESOLVE_ADDR":0x7000002D,
        "DT_MIPS_PERF_SUFFIX":0x7000002E,
        "DT_MIPS_COMPACT_SIZE":0x7000002F,
        "DT_MIPS_GP_VALUE":0x70000030,
        "DT_MIPS_AUX_DYNAMIC":0x70000031,
        "DT_MIPS_PLTGOT":0x70000032,
        "DT_MIPS_RWPLT":0x70000034,
        "DT_MIPS_RLD_MAP_REL":0x70000035,
        "DT_AUXILIARY":0x7FFFFFFD,
        "DT_FILTER":0x7FFFFFFF}

    def __init__(self):
        self.d_tag = None    # 节的类型
        self.d_un = None     # 由d_tag决定此字段如何解析，可为地址（d_ptr）或者为值（d_val）

    def read_Dym(self, file: TextIOWrapper): 
        self.read_d_tag(file)
        self.read_d_un(file)

    @abc.abstractmethod
    def read_d_tag(self, file: TextIOWrapper):
        pass

    @abc.abstractmethod
    def read_d_un(self, file: TextIOWrapper):
        pass


