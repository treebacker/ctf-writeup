from pwn import *
import string
context.binary = './pwn1_sctf_2016'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20115)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn1_sctf_2016')

def dbg():
	raw_input()