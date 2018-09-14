#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ${NAME}.py
# @Author: yangshouguo
# @Date  : ${DATE}
# @Desc  : tools for basic analysis

import angr


# init_project
# get angr.project
def init_project(binary_path, default_options={"auto_load_libs": False}):
    return angr.Project(binary_path, load_options=default_options)


# get_function_addr_by_name
# param: proj:angr.Project func_name:str
def get_function_addr_by_name(proj, func_name):
    return proj.loader.find_symbol(func_name).linked_addr


# get_function_by_name
# param: proj:angr.Project func_name:str
# return ELFSymbol class of specific function
# below is it's attribute
'''
TYPE_FUNCTION = {int} 2
TYPE_NONE = {int} 1
TYPE_OBJECT = {int} 3
TYPE_OTHER = {int} 0
TYPE_SECTION = {int} 4
addr = {int} 4301004
binding = {str} 'STB_GLOBAL'
demangled_name = {unicode} u'ixmlNode_cloneNode'
elftype = {str} 'STT_FUNC'
is_common = {bool} False
is_export = {bool} True
is_extern = {bool} False
is_forward = {bool} False
is_function = {bool} True
is_import = {bool} False
is_local = {bool} False
is_static = {bool} False
is_weak = {bool} False
linked_addr = {int} 4301004
name = {unicode} u'ixmlNode_cloneNode'
owner_obj = {ELF} <ELF Object cgibin, maps [0x400000:0x436c5f]>
rebased_addr = {int} 4301004
relative_addr = {int} 106700
resolved = {bool} True
resolvedby = {ELFSymbol} <Symbol "ixmlNode_cloneNode" in cgibin at 0x41a0cc>
section = {int} 10
size = {int} 76
type = {int} 2
warned_addr = {bool} True
'''
def get_function_by_name(proj, func_name):
    return proj.loader.find_symbol(func_name)

# project.factory.block()
# return Block class
'''
BLOCK_MAX_SIZE = {int} 4096
_bytes = {NoneType} None
_capstone = {NoneType} None
_collect_data_refs = {bool} False
_instruction_addrs = {list} <type 'list'>: [4301004L, 4301008L, 4301012L, 4301016L, 4301020L]
_instructions = {int} 5
_opt_level = {NoneType} None
_project = {Project} <Project ./cgibin>
_vex = {IRSB} 
_vex_engine = {SimEngineVEX} <angr.engines.vex.engine.SimEngineVEX object at 0x7fbe51715b50>
_vex_nostmt = {NoneType} None
addr = {int} 4301004
arch = {ArchMIPS32} <Arch MIPS32 (LE)>
bytes = {str} '���\\' �� �� �!� '
capstone = {CapstoneBlock} ...
codenode = {BlockNode} <BlockNode at 0x41a0cc (size 20)>
instruction_addrs = {list} <type 'list'>: [4301004L, 4301008L, 4301012L, 4301016L, 4301020L]
instructions = {int} 5
size = {int} 20
thumb = {bool} False
vex = {IRSB} ...
vex_nostmt = {IRSB} ...
'''
def get_block_by_addr(proj, addr):
    return proj.factory.block(addr)

#VEX is a type of IR
# see https://docs.angr.io/docs/ir.html
# reture type : IRSB class
# below is attributes of IRSB
'''
addr = {int} 4301004
all_constants = {list} <type 'list'>...
arch = {ArchMIPS32} <Arch MIPS32 (LE)>
constant_jump_targets = {set} set([4301064, 4301024L])
constant_jump_targets_and_jumpkinds = {dict} {4301064: 'Ijk_Boring', 4301024L: 'Ijk_Boring'}
constants = {list} <type 'list'>...
data_refs = {NoneType} None
default_exit_target = {long} 4301024
direct_next = {bool} True
exit_statements = {tuple} <type 'tuple'>
expressions = {generator} <generator object expressions at 0x7f1674be0eb0>
has_statements = {list} ...
instruction_addresses = {tuple} <type 'tuple'>: (4301004L, 4301008L, 4301012L, 4301016L, 4301020L)
instructions = {int} 5
jumpkind = {str} 'Ijk_Boring'
next = {Const} 0x0041a0e0
offsIP = {int} 136
operations = {list} <type 'list'>: ['Iop_Add32', 'Iop_Add32', 'Iop_Add32', 'Iop_CmpEQ32']
size = {int} 20
statements = {list} ...
stmts_used = {int} 21
tyenv = {IRTypeEnv}...
'''
def get_block_vex_by_addr(proj, addr):
    return proj.factory.block(addr).vex

def test():
    proj = init_project('./cgibin')
    func = get_function_addr_by_name(proj, 'ixmlNode_cloneNode')
    block = get_block_vex_by_addr(proj, func)
    print block
    print str(block)

    print 'reteta'
    block = get_block_vex_by_addr(proj, func)
if __name__ == '__main__':
    test()
