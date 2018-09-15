#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ${NAME}.py
# @Author: yangshouguo
# @Date  : ${DATE}
# @Desc  : tools for basic analysis

import angr
import struct

# init_project
# get angr.Project
def init_project(binary_path, default_options={"auto_load_libs": False}):
    return angr.Project(binary_path, load_options=default_options)


# get_function_addr_by_name
# param: proj:angr.Project func_name:str
def get_function_addr_by_name(proj, func_name):
    return proj.loader.find_symbol(func_name).linked_addr

#get_CFG_of_binary
#param: proj:angr.Project , Fast:bool
'''
CFG的核心是[NetworkX](https://networkx.github.io/) di-graph。所有正常的NetworkX API都可用： 
定制化CFG：

| Option                           | Description                                                  |
| -------------------------------- | ------------------------------------------------------------ |
| context_sensitivity_level        | 设置分析的上下文敏感度级别 。默认为1。                       |
| starts                           | 地址列表（list），用作分析的入口点。                         |
| avoid_runs                       | 要在分析中忽略的地址列表（list）。                           |
| call_depth                       | 将分析的深度限制为某些数字调用。这对于检查特定函数可以直接跳转到哪些函数（通过将call_depth设置为1）非常有用。 |
| initial_state                    | 可以向CFG提供初始状态，它将在整个分析过程中使用。            |
| keep_state                       | 为了节省内存，默认情况下会丢弃每个基本块的状态。如果keep_state为True，则状态将保存在CFGNode中。 |
| enable_symbolic_back_traversal   | 是否启用强化技术来解决间接跳转 。                            |
| enable_advanced_backward_slicing | 是否启用另一种强化技术来解决直接跳转                         |
| more!                            | 检查`b.analyses.CFGAccurate`上的`docstring`以获取更多最新选项 |
'''
def get_CFG_of_binary(proj, Fast=True):
    if Fast:
        return proj.analyses.CFGFast()
    else:
        return proj.analyses.CFGAccurate()


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

#get_block_rawbyte_by_addr
#param: proj, addr
#return list which contains bytes value from block
def get_block_rawbyte_by_addr(proj, addr):
    bytes = proj.factory.block(addr).bytes
    return [hex(x) for x in struct.unpack('B'*len(bytes), bytes)]


def test():
    proj = init_project('./cgibin')
    func_addr = get_function_addr_by_name(proj, 'ixmlNode_cloneNode')

    func_bin = get_block_rawbyte_by_addr(proj, func_addr)

    print func_bin

if __name__ == '__main__':
    test()
