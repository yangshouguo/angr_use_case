#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ${NAME}.py
# @Author: yangshouguo
# @Date  : ${DATE}
# @Desc  : tools for basic analysis

import angr
import struct
from collections import deque

# init_project
# get angr.Project
def init_project(binary_path, default_options={"auto_load_libs": False}):
    try:
        return angr.Project(binary_path, load_options=default_options)
    except Exception,e:
        print str(e)
        return None

#return arch info like arm,mips
def get_archinfo(proj):
    return proj.arch.name

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
    try:
        if Fast:
            return proj.analyses.CFGFast()
        else:
            return proj.analyses.CFGAccurate()
    except Exception, e:
        print str(e)

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

#
def get_function_blocks(proj, addr):
    next_addrs = deque([addr])
    all_addrs = set()
    all_addrs.add(addr)
    while len(next_addrs) > 0:
        curr_addr = next_addrs.popleft()
        next_adrs = get_next_blocks_by_addr(proj, curr_addr)
        next_adrs = set(next_adrs) - all_addrs # get difference set
        all_addrs |= next_adrs
        next_addrs += list(next_adrs)

    return all_addrs



#get_next_blocks_by_addr
#param:
#return the jump targets of the block with addr
def get_next_blocks_by_addr(proj, addr):
    return proj.factory.block(addr).vex.constant_jump_targets

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

#get a list contains capstone of block
def get_block_asm_by_addr(proj, addr):
    # print dir(proj.factory.block(addr).capstone.insns)
    return [ x.insn.mnemonic+', '+x.insn.op_str for x in proj.factory.block(addr).capstone.insns]


# get all asm blocks of this function in form of dict {blockaddr:block_asm_list}
# concatenate : combine all blocks asm to one
def get_function_asm_by_addr(proj, cfg, addr, concatenate = False):

    dic = {}
    for block in get_cfg_blocks_by_addr(cfg ,addr):
        # print hex(block.addr)
        dic[block.addr] = get_block_asm_by_addr(proj, block.addr)

    if concatenate:
        con_list = []
        for addr in sorted(dic.keys()):
            con_list += list(dic[addr])
        return con_list

    return dic

'''
`Functions`的重要属性：

- `entry_func.block_addrs` ：该函数的一组基本块的起始地址（类型：*dictionary-keyiterator*）。
- `entry_func.blocks` ：属于该函数的一组基本块，可以使用`capstone`进行`explore`和反汇编 ？？？？。
- `entry_func.string_references()` ：返回函数中任何点引用的所有常量字符串的列表（list）。它们被格式化为`(addr，string)`元组，其中`addr`是字符串所在的二进制数据部分中的地址，而`string`是包含字符串值的python字符串。 
- `entry_func.returning`：是一个布尔值，表示函数是否可以返回。 `False`表示所有路径都不返回。 
- `entry_func.callable`：是一个指向此函数的`angr Callable`对象。可以像使用python参数的python函数一样调用它并获取实际结果（可能是符号）。？？？？ 
- `entry_func.transition_graph`： 是一个NetworkX DiGraph，描述了函数本身内的控制流。它类似于IDA在每个函数级别上显示的控制流图。 
- `entry_func.name` ：函数名字。
- `entry_func.has_unresolved_calls` and `entry.has_unresolved_jumps`： 与检测CFG内的不精确有关。有时，分析无法检测间接调用或跳转的可能目标是什么。如果在函数内发生这种情况，则该函数将相应的`has_unresolved_ *`值设置为`True`。 
- `entry_func.get_call_sites()`： 返回所有以调用其他函数（的语句）结束的基本块的地址列表。 
- `entry_func.get_call_target(callsite_addr)`： 将从call site地址列表中给出`callsite_addr`，返回该callsite将会调用的位置。 ？？？？
- `entry_func.get_call_return(callsite_addr)` ： 将从call site地址列表中给出`callsite_addr`，返回该callsite将会返回的位置。 ？？？？
'''
def get_cfg_function_by_addr(cfg, addr):
    return cfg.kb.functions[addr]

def get_cfg_function_by_name(cfg, function_name):
    return cfg.kb.functions.Function[function_name]

def get_cfg_Callable_by_addr(cfg, addr):
    return cfg.kb.functions[addr].callable


def get_cfg_blocks_by_addr(cfg, addr):
    if addr in cfg.kb.functions:
        return cfg.kb.functions[addr].blocks
    return []

#get_all_functions
#return a list containing all addr
#slowly
def get_all_functions(proj):
    obj = proj.loader.main_object
    #remove the imported functions
    return [x for x in list(set(obj.symbols_by_addr.keys()) - set(obj.plt.values())) if x > 10]

#return function name through function address
def get_function_name_by_addr(proj, addr):
    if proj.loader.find_symbol(addr):
        return proj.loader.find_symbol(addr).name

#TODO:get right semantic of block
def run_blocks(proj ,addr):
    state = proj.factory.blank_state(addr = addr)
    while True:
        succ = state.step()
        if len(succ.successors) == 2:
            break
        state = succ.successors[0]

    state1 =  succ.successors[0]
    regs = state1.regs
    print dir(regs)


#TODO:get right semantic of function
# get result from register v0 of MIPS , rax of X86,
def run_function(proj, func_addr):
    target_function = proj.factory.callable(func_addr)
    result = target_function() # result : claripy.ast.bv.BV

    # regs = target_function.result_state.regs.v0
    # print target_function.result_state.regs.v0

    # result_path_group to look all path
    for path in  target_function.result_path_group.active:
        print dir(path)
        print type(path)



    # print type(result)
    print dir(result)
    # print differen paths
    # for arg in result.args:
    #     print (arg)

    print result.variables
    print result

def run_function2(proj, func_addr):
    cfg = proj.analyses.CFGFast()
    state = proj.factory.call_state(addr=func_addr)
    simgr = proj.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=10))
    while len(simgr.active) != 0:
        simgr.step()
        print simgr.active

#[(400, 1), (710, 1), (430, 1), (180, 1), (440, 1), (460, 1), (210, 1), (1390, 1), (260, 2), (200, 2), (240, 2), (140, 3), (150, 3), (290, 3), (90, 3), (120, 3), (110, 4), (70, 5), (100, 5), (50, 6), (30, 7), (40, 10), (60, 10), (80, 10), (20, 12), (10, 17), (0, 123)]
def StatisticsInstrLengthOfFunction():
    proj = init_project('./cgibin', default_options={'auto_load_libs':False})


    cfg = get_CFG_of_binary(proj)
    addr = get_function_addr_by_name(proj, 'MD5Final')

    se = {}
    functions = get_all_functions(proj)
    for funcaddr in functions:
        t = get_function_asm_by_addr(proj, cfg, funcaddr)
        leng  = 0
        for x in t:
            leng += len(t[x])
        nor_l = (leng/10)*10

        if nor_l in se:
            se[nor_l] += 1
        else:
            se[nor_l] = 1

    print sorted(se.items(), key = lambda item:item[1] )


def test():
    proj = init_project('./cgibin', default_options={'auto_load_libs':False})

    t =  get_archinfo(proj)
    print dir(t)
    print t


if __name__ == '__main__':
    test()