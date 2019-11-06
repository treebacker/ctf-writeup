#-*- coding:utf-8 -*-
import angr
import sys
import claripy

def and0(c):
	return claripy.And(0x61 <=c, c<=0x66)

print("[*]start------------------------------------")
p = angr.Project('puzzle.exe', load_options={'auto_load_libs': False})
state = p.factory.entry_state() # entry 

length = 16
flag = claripy.BVS('aaaa', length*8)

for i in range(length):
	state.slover.add(and0(flag.get_byte(i)))

print("[*]simgr start-------------------------------")
 
my_buf = 0x004124D6         #
state.memory.store(addr=my_buf, data=flag)# 吧约束的字符串放入该地址
state.regs.rdi = my_buf# rdi指向该地址


@p.hook(0x00401C70) #勾取
def debug_func(state):
    rdi_value = state.regs.rdi 
    print ( 'rdi is point to {}'.format(rdi_value) )
    

sm = p.factory.simulation_manager(state)

for pp in sm.found:
    out = pp.posix.dumps(1)   # 表示程序的输出
    print (out)
    inp = pp.posix.files[0].all_bytes()  # 取输入的变量
    print(pp.solver.eval(inp,cast_to = str))  # 利用约束求解引擎求解输入
