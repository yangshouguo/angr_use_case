#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : ExtractFunctionAsm.py
# @Author: Yangshouguo
# @Date  : 18-9-24
# @Desc  : this script can extract disassembly of function

from function_info import *
import json, os, sys

DST_DIR = 'ASM_DATASET'
class ExtractFunctionDisasm():
    def __init__(self, binary_path):
        pass
        self.proj = init_project(binary_path)
        if self.proj:
            self.all_function_addr = get_all_functions(self.proj)
            self.cfg = get_CFG_of_binary(self.proj)

    def GetFuncInfo(self, func_addr):
        return get_function_asm_by_addr(self.proj, self.cfg, func_addr, concatenate=True)

    def GetAllFunctionInfo(self):
        #二进制文件的cfg分析失败!!!很常见, 这可能是为什么iDA收费的原因
        if not self.proj or not self.cfg:
            return {}

        dic = {}
        for addr in get_all_functions(self.proj):

            # 跳过系统函数
            if str(get_function_name_by_addr(self.proj, addr=addr)).startswith('_') or str(
                    get_function_name_by_addr(self.proj, addr=addr)).startswith('__'):
                continue

            dic[get_function_name_by_addr(self.proj, addr)] = {}
            dic[get_function_name_by_addr(self.proj, addr)]['addr'] = addr
            dic[get_function_name_by_addr(self.proj, addr)]['asm'] = self.GetFuncInfo(addr)
            dic[get_function_name_by_addr(self.proj, addr)]['arch'] = get_archinfo(self.proj)

        return dic


def load_asm_json(file_path):
    print file_path
    with open(file_path, 'r') as f:
        dic = json.load(f)
        return dic


def generate_function_pair(bin_name, dir1, dir2):
    generate_dataset(fromdir=os.path.join(dir1, bin_name), todir=os.path.join(DST_DIR,dir1, bin_name))
    generate_dataset(fromdir=os.path.join(dir2, bin_name), todir=os.path.join(DST_DIR,dir2, bin_name))

    dic1 = load_asm_json(os.path.join(DST_DIR,dir1, bin_name))
    dic2 = load_asm_json(os.path.join(DST_DIR, dir2, bin_name))

    dic1_functions = set(dic1.keys())
    dic2_functions = set(dic2.keys())
    union_functions = dic1_functions & dic2_functions
    new_dic = {}
    for function in union_functions:

        # 剔除小函数
        if len(dic1[function]['asm']) < 5 or len(dic2[function]['asm']):
            continue

        new_dic.setdefault(function, {})['asm1'] = dic1[function]
        new_dic.setdefault(function, {})['asm2'] = dic2[function]


    return new_dic


# TODO:讲 fromdir的二进制文件提取汇编信息保存到todir的对应路径中
# 例如 /fromdir/x86/cgibin --> /rodir/x86/cgibin_asm.json
def generate_dataset(fromdir, todir):
    if os.path.exists(todir):
        return

    efd = ExtractFunctionDisasm(fromdir)
    dic = efd.GetAllFunctionInfo()

    if not os.path.exists(os.path.split(todir)[0]):
        os.makedirs(os.path.split(todir)[0])

    with open(todir, 'w') as f:
        json.dump(dic, f, indent=4)


if __name__ == '__main__':


    # change work dir
    WORK_DIR = '/home/ubuntu/disk/ssd_3/workspace/dataset_binaries'
    os.chdir(WORK_DIR)

    # 生成asm文件
    # with open('notstripped_seed', 'r') as f:
    #     lines = f.readlines()
    #     for line in lines:
    #         line = line.strip()
    #         generate_dataset(fromdir=line, todir=os.path.join(dst, line + '_asm.json'))

    # 生成函数对
    dic = {}
    with open('notstripped_seed', 'r') as f:
        lines = f.readlines()
        # 对文件分组，将相同名字但是在不同文件夹中的文件进行分组
        for line in lines:
            line = line.strip()
            split_line = line.split('/')
            # allfile.append(split_line)
            dic.setdefault(split_line[2], []).append(split_line[1])
        # sorted_files = sorted(allfile, key=lambda x:x[2])

    '''
    生成相同二进制文件不同的组合
    SHA.so ARM-gcc-default PPC-gcc-default
    SHA.so ARM-gcc-default MIPS-gcc-default
    SHA.so ARM-gcc-default X86-gcc-default
    SHA.so PPC-gcc-default PPC-gcc-default
    SHA.so PPC-gcc-default MIPS-gcc-default
    SHA.so PPC-gcc-default X86-gcc-default
    SHA.so MIPS-gcc-default PPC-gcc-default
    SHA.so MIPS-gcc-default MIPS-gcc-default
    SHA.so MIPS-gcc-default X86-gcc-default
    '''

    ASM_PAIR_DATASET = 'ASM_PAIR_DATASET'
    if not os.path.exists(ASM_PAIR_DATASET):
        os.makedirs(ASM_PAIR_DATASET)
    for binfile in dic:
        if len(dic[binfile]) > 1:
            for i in range(len(dic[binfile]) - 1):
                for j in range(1, len(dic[binfile])):
                    # print binfile, dic[binfile][i], dic[binfile][j]
                    dic_pair = generate_function_pair(binfile, dic[binfile][i], dic[binfile][j])
                    with open(os.path.join(ASM_PAIR_DATASET,
                                           '_'.join([binfile, dic[binfile][i], dic[binfile][j]])), 'w') as tf:
                        json.dump(dic_pair, tf, indent=4)
