#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ExtractFunctionAsm.py
# @Author: Yangshouguo
# @Date  : 18-9-24
# @Desc  : this script can extract disassembly of function

from function_info import *

class ExtractFunctionDisasm():
    def __init__(self, binary_path):
        pass
        self.proj = init_project(binary_path)
        self.all_function_addr = get_all_functions(self.proj)
        self.cfg = get_CFG_of_binary(self.proj)

    def GetFuncInfo(self, func_addr):
        return get_function_asm_by_addr(self.proj, self.cfg, func_addr)

    def GetAllFunctionInfo(self):
        dic = {}
        for addr in get_all_functions(self.proj):
            dic[get_function_name_by_addr(self.proj, addr)] = {}
            dic[get_function_name_by_addr(self.proj, addr)]['addr'] = addr
            dic[get_function_name_by_addr(self.proj, addr)]['asm'] = self.GetFuncInfo(addr)

        return dic


efd = ExtractFunctionDisasm('./cgibin')
dic = efd.GetAllFunctionInfo()
import json
with open('cgibin.json','w') as f:
    json.dump(dic, f,indent=4)
