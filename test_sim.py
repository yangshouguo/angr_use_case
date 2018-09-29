#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @File  : test_sim.py.py
# @Author: Yangshouguo
# @Date  : 18-9-21
# @Desc  :

import angr
import sys

print "[*]start------------------------------------"
p = angr.Project(sys.argv[1])  # 建立工程初始化二进制文件
state = p.factory.blank_state(addr=0x2c50c)  # 获取入口点处状态

'''
state.posix.files[0].read_from(1)表示从标准输入读取一个字节
'''


print "[*]simgr start-------------------------------"

sm = p.factory.simgr(state)  # 初始化进程模拟器
sm.explore(find=lambda s: "passwd" in s.posix.dumps(2))  # 寻找运行过程中存在 “correct！”的路径，并丢弃其他路径
print "[*]program excuted---------------------------"

print len(sm.found)

for pp in sm.found:
    print pp.se._solver.result.model