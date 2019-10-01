from pwn import *
context.binary = './pwn1'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

p = process('./pwn1')

def dbg():
	raw_input()

def choice(ch):
	p.recvuntil('Your choice : ')
	p.send(str(ch))

def add(content, level):
	size = len(content)
	choice(1)
	p.recvuntil('Length of the name :')
	p.sendline(str(size))
	p.recvuntil('The name of this life :')
	p.send(content)
	p.recvuntil('The level of this life (High/Low) :')
	p.sendline(level)
	print "create a chunk success"

def show(idx):
	choice(2)

def delete(idx):
	choice(3)
	p.recvuntil('Which life do you want to remove: ')
	p.sendline(str(idx))
	print "delete a chunk success"

def destory():
	choice(4)
	print "destory success!"

gdb.attach(p, 'b* 0x400E51')
add('a'*0x80, 'Low')


p.interactive()
p.close()

