from pwn import *
from LibcSearcher import *
context.binary = './swap_ret'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('47.106.94.13', 50009)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./swap_ret')
	gdb.attach(p, 'b* 0x0804872E')


