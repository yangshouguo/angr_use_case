#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : test.py
# @Author: Yangshouguo
# @Date  : 18-9-15
# @Desc  :
import json,os,sys

def load_asm_json(file_path):
    with open(file_path,'r') as f:
        dic = json.load(f)
        return dic


def generate_function_pair(bin_name, dir1, dir2):
    dic1 = load_asm_json(os.path.join(dir1, bin_name))
    dic2 = load_asm_json(os.path.join(dir2, bin_name))

    dic1_functions = set(dic1.keys())
    dic2_functions = set(dic2.keys())
    union_functions = dic1_functions & dic2_functions
    new_dic = {}
    for function in union_functions:
        new_dic.setdefault(function, {})['asm1'] = dic1[function]
        new_dic.setdefault(function, {})['asm2'] = dic2[function]


    return new_dic



if __name__ == '__main__':

    dic = {}
    with open('notstripped_seed', 'r') as f:
        lines = f.readlines()
        # 对文件分组，讲相同名字但是在不同文件夹中的文件进行分组
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
    os.makedirs(ASM_PAIR_DATASET)
    for binfile in dic:
        if len(dic[binfile]) > 1:
            for i in range(len(dic[binfile])-1):
                for j in range(1, len(dic[binfile])):
                    # print binfile, dic[binfile][i], dic[binfile][j]
                    dic = generate_function_pair(binfile, dic[binfile][i], dic[binfile][j])
                    with open(os.path.join(ASM_PAIR_DATASET, '_'.join([binfile, dic[binfile][i], dic[binfile][j]]))) as tf:
                        json.dump(dic, tf, indent=4)



